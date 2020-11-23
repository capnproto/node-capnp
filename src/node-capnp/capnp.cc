// Copyright (c) 2014 Sandstorm Development Group, Inc. and contributors
// Licensed under the MIT License:
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#if __cplusplus >= 201300
// Hack around stdlib bug with C++14.
#include <initializer_list>  // force libstdc++ to include its config
#undef _GLIBCXX_HAVE_GETS    // correct broken config
// End hack.
#endif

#include <node.h>
#include <node_buffer.h>
#include <nan.h>
#include <capnp/dynamic.h>
#include <capnp/schema-parser.h>
#include <kj/debug.h>
#include <uv.h>
#include <kj/async.h>
#include <kj/async-io.h>
#include <kj/io.h>
#include <kj/vector.h>
#include <errno.h>
#include <unistd.h>
#include <capnp/rpc-twoparty.h>
#include <capnp/rpc.capnp.h>
#include <capnp/serialize.h>
#include <capnp/serialize-packed.h>
#include <unordered_map>
#include <inttypes.h>
#include <set>
#include <stdlib.h>
#include <sys/uio.h>

#include <typeinfo>
#include <typeindex>
#include <cxxabi.h>

#ifdef SANDSTORM_BUILD
#include <sodium/crypto_stream_chacha20.h>
#endif

namespace v8capnp {
namespace {  // so we get warnings if anything declared in this file is left undefined...

typedef unsigned char byte;
typedef unsigned int uint;

// =======================================================================================
// KJ <-> libuv glue.

#define UV_CALL(code, loop, ...) \
  { \
    auto result = code; \
    KJ_ASSERT(result == 0, uv_strerror(result), ##__VA_ARGS__); \
  }

template <typename HandleType>
class UvHandle {
  // Encapsulates libuv handle lifetime into C++ object lifetime. This turns out to be hard.
  // If the loop is no longer running, memory will leak.
  //
  // Use like:
  //   UvHandle<uv_timer_t> timer(uv_timer_init, loop);
  //   uv_timer_start(timer, &callback, 0, 0);

public:
  template <typename ConstructorFunc, typename... Args>
  UvHandle(ConstructorFunc&& func, uv_loop_t* loop, Args&&... args): handle(new HandleType) {
    auto result = func(loop, handle, kj::fwd<Args>(args)...);
    if (result < 0) {
      delete handle;
      auto error = uv_strerror(result);
      KJ_FAIL_ASSERT("creating UV handle failed", error);
    }
  }

  ~UvHandle() {
    uv_close(getBase(), &closeCallback);
  }

  inline HandleType& operator*() { return *handle; }
  inline const HandleType& operator*() const { return *handle; }

  inline HandleType* operator->() { return handle; }
  inline HandleType* operator->() const { return handle; }

  inline operator HandleType*() { return handle; }
  inline operator const HandleType*() const { return handle; }

  inline operator uv_handle_t*() { return reinterpret_cast<uv_handle_t*>(handle); }
  inline operator const uv_handle_t*() const { return reinterpret_cast<uv_handle_t*>(handle); }

  inline HandleType* get() { return handle; }
  inline HandleType* get() const { return handle; }

  inline uv_handle_t* getBase() { return reinterpret_cast<uv_handle_t*>(handle); }
  inline uv_handle_t* getBase() const { return reinterpret_cast<uv_handle_t*>(handle); }

private:
  HandleType* handle;

  static void closeCallback(uv_handle_t* handle) {
    delete reinterpret_cast<HandleType*>(handle);
  }
};

class UvEventPort: public kj::EventPort {
public:
  UvEventPort(uv_loop_t* loop)
      : loop(loop),
        timer(uv_timer_init, loop),
        kjLoop(*this) {
    timer->data = this;
  }
  ~UvEventPort() {
    if (scheduled) {
      UV_CALL(uv_timer_stop(timer), loop);
    }
  }

  kj::EventLoop& getKjLoop() { return kjLoop; }
  uv_loop_t* getUvLoop() { return loop; }

  bool wait() override {
    UV_CALL(uv_run(loop, UV_RUN_ONCE), loop);

    // TODO(someday): Implement cross-thread wakeup.
    return false;
  }

  bool poll() override {
    UV_CALL(uv_run(loop, UV_RUN_NOWAIT), loop);

    // TODO(someday): Implement cross-thread wakeup.
    return false;
  }

  void setRunnable(bool runnable) override {
    if (runnable != this->runnable) {
      this->runnable = runnable;
      if (runnable && !scheduled) {
        schedule();
      }
    }
  }

private:
  uv_loop_t* loop;
  UvHandle<uv_timer_t> timer;
  kj::EventLoop kjLoop;
  bool runnable = false;
  bool scheduled = false;

  void schedule() {
    UV_CALL(uv_timer_start(timer, &doRun, 0, 0), loop);
    scheduled = true;
  }

  void run() {
    KJ_ASSERT(scheduled);

    UV_CALL(uv_timer_stop(timer), loop);

    if (runnable) {
      kjLoop.run();
    }

    if (runnable) {
      // Apparently either we never became non-runnable, or we did but then became runnable again.
      // Since `scheduled` has been true the whole time, we won't have been rescheduled, so do that
      // now.
      KJ_LOG(WARNING, "still runnable after kjLoop.run()?");
      schedule();
    } else {
      scheduled = false;
    }
  }

  static void doRun(uv_timer_t* handle) {
    KJ_ASSERT(handle != nullptr);
    UvEventPort* self = reinterpret_cast<UvEventPort*>(handle->data);
    self->run();
  }
};

static void setNonblocking(int fd) {
  int flags;
  KJ_SYSCALL(flags = fcntl(fd, F_GETFL));
  if ((flags & O_NONBLOCK) == 0) {
    KJ_SYSCALL(fcntl(fd, F_SETFL, flags | O_NONBLOCK));
  }
}

static void setCloseOnExec(int fd) {
  int flags;
  KJ_SYSCALL(flags = fcntl(fd, F_GETFD));
  if ((flags & FD_CLOEXEC) == 0) {
    KJ_SYSCALL(fcntl(fd, F_SETFD, flags | FD_CLOEXEC));
  }
}

static int applyFlags(int fd, uint flags) {
  if (flags & kj::LowLevelAsyncIoProvider::ALREADY_NONBLOCK) {
    KJ_DREQUIRE(fcntl(fd, F_GETFL) & O_NONBLOCK, "You claimed you set NONBLOCK, but you didn't.");
  } else {
    setNonblocking(fd);
  }

  if (flags & kj::LowLevelAsyncIoProvider::TAKE_OWNERSHIP) {
    if (flags & kj::LowLevelAsyncIoProvider::ALREADY_CLOEXEC) {
      KJ_DREQUIRE(fcntl(fd, F_GETFD) & FD_CLOEXEC,
                  "You claimed you set CLOEXEC, but you didn't.");
    } else {
      setCloseOnExec(fd);
    }
  }

  return fd;
}

static constexpr uint NEW_FD_FLAGS =
#if __linux__
    kj::LowLevelAsyncIoProvider::ALREADY_CLOEXEC | kj::LowLevelAsyncIoProvider::ALREADY_NONBLOCK |
#endif
    kj::LowLevelAsyncIoProvider::TAKE_OWNERSHIP;
// We always try to open FDs with CLOEXEC and NONBLOCK already set on Linux, but on other platforms
// this is not possible.

class OwnedFileDescriptor {
public:
  OwnedFileDescriptor(uv_loop_t* loop, int fd, uint flags)
      : uvLoop(loop), fd(applyFlags(fd, flags)), flags(flags),
        uvPoller(uv_poll_init, uvLoop, fd) {
    uvPoller->data = this;
    UV_CALL(uv_poll_start(uvPoller, 0, &pollCallback), uvLoop);
  }

  ~OwnedFileDescriptor() noexcept(false) {
    if (!stopped) {
      UV_CALL(uv_poll_stop(uvPoller), uvLoop);
    }

    // Don't use KJ_SYSCALL() here because close() should not be repeated on EINTR.
    if ((flags & kj::LowLevelAsyncIoProvider::TAKE_OWNERSHIP) && close(fd) < 0) {
      KJ_FAIL_SYSCALL("close", errno, fd) {
        // Recoverable exceptions are safe in destructors.
        break;
      }
    }
  }

  kj::Promise<void> onReadable() {
    if (stopped) return kj::READY_NOW;

    KJ_REQUIRE(readable == nullptr, "Must wait for previous event to complete.");

    auto paf = kj::newPromiseAndFulfiller<void>();
    readable = kj::mv(paf.fulfiller);

    int flags = UV_READABLE | (writable == nullptr ? 0 : UV_WRITABLE);
    UV_CALL(uv_poll_start(uvPoller, flags, &pollCallback), uvLoop);

    return kj::mv(paf.promise);
  }

  kj::Promise<void> onWritable() {
    if (stopped) return kj::READY_NOW;

    KJ_REQUIRE(writable == nullptr, "Must wait for previous event to complete.");

    auto paf = kj::newPromiseAndFulfiller<void>();
    writable = kj::mv(paf.fulfiller);

    int flags = UV_WRITABLE | (readable == nullptr ? 0 : UV_READABLE);
    UV_CALL(uv_poll_start(uvPoller, flags, &pollCallback), uvLoop);

    return kj::mv(paf.promise);
  }

protected:
  uv_loop_t* const uvLoop;
  const int fd;

private:
  uint flags;
  kj::Maybe<kj::Own<kj::PromiseFulfiller<void>>> readable;
  kj::Maybe<kj::Own<kj::PromiseFulfiller<void>>> writable;
  bool stopped = false;
  UvHandle<uv_poll_t> uvPoller;

  static void pollCallback(uv_poll_t* handle, int status, int events) {
    reinterpret_cast<OwnedFileDescriptor*>(handle->data)->pollDone(status, events);
  }

  void pollDone(int status, int events) {
    if (status != 0) {
      // Error.  libuv produces a non-zero status if polling produced POLLERR.  The error code
      // reported by libuv is always EBADF, even if the file descriptor is perfectly legitimate but
      // has simply become disconnected.  Instead of throwing an exception, we'd rather report
      // that the fd is now readable/writable and let the caller discover the error when they
      // actually attempt to read/write.
      KJ_IF_MAYBE(r, readable) {
        r->get()->fulfill();
        readable = nullptr;
      }
      KJ_IF_MAYBE(w, writable) {
        w->get()->fulfill();
        writable = nullptr;
      }

      // libuv automatically performs uv_poll_stop() before calling poll_cb with an error status.
      stopped = true;

    } else {
      // Fire the events.
      if (events & UV_READABLE) {
        KJ_ASSERT_NONNULL(readable)->fulfill();
        readable = nullptr;
      }
      if (events & UV_WRITABLE) {
        KJ_ASSERT_NONNULL(writable)->fulfill();
        writable = nullptr;
      }

      // Update the poll flags.
      int flags = (readable == nullptr ? 0 : UV_READABLE) |
                  (writable == nullptr ? 0 : UV_WRITABLE);
      UV_CALL(uv_poll_start(uvPoller, flags, &pollCallback), uvLoop);
    }
  }
};

class UvIoStream: public OwnedFileDescriptor, public kj::AsyncIoStream {
  // IoStream implementation on top of libuv.  This is mostly a copy of the UnixEventPort-based
  // implementation in kj/async-io.c++.  We use uv_poll, which the libuv docs say is slow
  // "especially on Windows".  I'm guessing it's not so slow on Unix, since it matches the
  // underlying APIs.
  //
  // TODO(cleanup):  Allow better code sharing between the two.

public:
  UvIoStream(uv_loop_t* loop, int fd, uint flags)
      : OwnedFileDescriptor(loop, fd, flags) {}
  virtual ~UvIoStream() noexcept(false) {}

  kj::Promise<size_t> read(void* buffer, size_t minBytes, size_t maxBytes) override {
    return tryReadInternal(buffer, minBytes, maxBytes, 0).then([=](size_t result) {
      KJ_REQUIRE(result >= minBytes, "Premature EOF") {
        // Pretend we read zeros from the input.
        memset(reinterpret_cast<byte*>(buffer) + result, 0, minBytes - result);
        return minBytes;
      }
      return result;
    });
  }

  kj::Promise<size_t> tryRead(void* buffer, size_t minBytes, size_t maxBytes) override {
    return tryReadInternal(buffer, minBytes, maxBytes, 0);
  }

  kj::Promise<void> write(const void* buffer, size_t size) override {
    ssize_t writeResult;
    KJ_NONBLOCKING_SYSCALL(writeResult = ::write(fd, buffer, size)) {
      return kj::READY_NOW;
    }

    // A negative result means EAGAIN, which we can treat the same as having written zero bytes.
    size_t n = writeResult < 0 ? 0 : writeResult;

    if (n == size) {
      return kj::READY_NOW;
    } else {
      buffer = reinterpret_cast<const byte*>(buffer) + n;
      size -= n;
    }

    return onWritable().then([=]() {
      return write(buffer, size);
    });
  }

  kj::Promise<void> write(kj::ArrayPtr<const kj::ArrayPtr<const byte>> pieces) override {
    if (pieces.size() == 0) {
      return writeInternal(nullptr, nullptr);
    } else {
      return writeInternal(pieces[0], pieces.slice(1, pieces.size()));
    }
  }

  void shutdownWrite() override {
    // There's no legitimate way to get an AsyncStreamFd that isn't a socket through the
    // UnixAsyncIoProvider interface.
    KJ_SYSCALL(shutdown(fd, SHUT_WR));
  }

#if CAPNP_VERSION >= 8000
  kj::Promise<void> whenWriteDisconnected() override {
    // TODO(someday): Implement using UV_DISCONNECT?
    return kj::NEVER_DONE;
  }
#endif

private:
  kj::Promise<size_t> tryReadInternal(void* buffer, size_t minBytes, size_t maxBytes,
                                      size_t alreadyRead) {
    // `alreadyRead` is the number of bytes we have already received via previous reads -- minBytes,
    // maxBytes, and buffer have already been adjusted to account for them, but this count must
    // be included in the final return value.

    ssize_t n;
    KJ_NONBLOCKING_SYSCALL(n = ::read(fd, buffer, maxBytes)) {
      return alreadyRead;
    }

    if (n < 0) {
      // Read would block.
      return onReadable().then([=]() {
        return tryReadInternal(buffer, minBytes, maxBytes, alreadyRead);
      });
    } else if (n == 0) {
      // EOF -OR- maxBytes == 0.
      return alreadyRead;
    } else if (kj::implicitCast<size_t>(n) < minBytes) {
      // The kernel returned fewer bytes than we asked for (and fewer than we need).  This indicates
      // that we're out of data.  It could also mean we're at EOF.  We could check for EOF by doing
      // another read just to see if it returns zero, but that would mean making a redundant syscall
      // every time we receive a message on a long-lived connection.  So, instead, we optimistically
      // asume we are not at EOF and return to the event loop.
      //
      // If libuv provided notification of HUP or RDHUP, we could do better here...
      buffer = reinterpret_cast<byte*>(buffer) + n;
      minBytes -= n;
      maxBytes -= n;
      alreadyRead += n;
      return onReadable().then([=]() {
        return tryReadInternal(buffer, minBytes, maxBytes, alreadyRead);
      });
    } else {
      // We read enough to stop here.
      return alreadyRead + n;
    }
  }

  kj::Promise<void> writeInternal(kj::ArrayPtr<const byte> firstPiece,
                                  kj::ArrayPtr<const kj::ArrayPtr<const byte>> morePieces) {
    KJ_STACK_ARRAY(struct iovec, iov, 1 + morePieces.size(), 16, 128);

    // writev() interface is not const-correct.  :(
    iov[0].iov_base = const_cast<byte*>(firstPiece.begin());
    iov[0].iov_len = firstPiece.size();
    for (uint i = 0; i < morePieces.size(); i++) {
      iov[i + 1].iov_base = const_cast<byte*>(morePieces[i].begin());
      iov[i + 1].iov_len = morePieces[i].size();
    }

    ssize_t writeResult;
    KJ_NONBLOCKING_SYSCALL(writeResult = ::writev(fd, iov.begin(), iov.size())) {
      // Error.

      // We can't "return kj::READY_NOW;" inside this block because it causes a memory leak due to
      // a bug that exists in both Clang and GCC:
      //   http://gcc.gnu.org/bugzilla/show_bug.cgi?id=33799
      //   http://llvm.org/bugs/show_bug.cgi?id=12286
      goto error;
    }
    if (false) {
    error:
      return kj::READY_NOW;
    }

    // A negative result means EAGAIN, which we can treat the same as having written zero bytes.
    size_t n = writeResult < 0 ? 0 : writeResult;

    // Discard all data that was written, then issue a new write for what's left (if any).
    for (;;) {
      if (n < firstPiece.size()) {
        // Only part of the first piece was consumed.  Wait for POLLOUT and then write again.
        firstPiece = firstPiece.slice(n, firstPiece.size());
        return onWritable().then([=]() {
          return writeInternal(firstPiece, morePieces);
        });
      } else if (morePieces.size() == 0) {
        // First piece was fully-consumed and there are no more pieces, so we're done.
        KJ_DASSERT(n == firstPiece.size(), n);
        return kj::READY_NOW;
      } else {
        // First piece was fully consumed, so move on to the next piece.
        n -= firstPiece.size();
        firstPiece = morePieces[0];
        morePieces = morePieces.slice(1, morePieces.size());
      }
    }
  }
};

class UvConnectionReceiver final: public kj::ConnectionReceiver, public OwnedFileDescriptor {
  // Like UvIoStream but for ConnectionReceiver.  This is also largely copied from kj/async-io.c++.

public:
  UvConnectionReceiver(uv_loop_t* loop, int fd, uint flags)
      : OwnedFileDescriptor(loop, fd, flags) {}

  kj::Promise<kj::Own<kj::AsyncIoStream>> accept() override {
    int newFd;

  retry:
#if __linux__
    newFd = ::accept4(fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    newFd = ::accept(fd, nullptr, nullptr);
#endif

    if (newFd >= 0) {
      return kj::Own<kj::AsyncIoStream>(kj::heap<UvIoStream>(uvLoop, newFd, NEW_FD_FLAGS));
    } else {
      int error = errno;

      switch (error) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
          // Not ready yet.
          return onReadable().then([this]() {
            return accept();
          });

        case EINTR:
        case ENETDOWN:
        case EPROTO:
        case EHOSTDOWN:
        case EHOSTUNREACH:
        case ENETUNREACH:
        case ECONNABORTED:
        case ETIMEDOUT:
          // According to the Linux man page, accept() may report an error if the accepted
          // connection is already broken.  In this case, we really ought to just ignore it and
          // keep waiting.  But it's hard to say exactly what errors are such network errors and
          // which ones are permanent errors.  We've made a guess here.
          goto retry;

        default:
          KJ_FAIL_SYSCALL("accept", error);
      }

    }
  }

  uint getPort() override {
    socklen_t addrlen;
    union {
      struct sockaddr generic;
      struct sockaddr_in inet4;
      struct sockaddr_in6 inet6;
    } addr;
    addrlen = sizeof(addr);
    KJ_SYSCALL(::getsockname(fd, &addr.generic, &addrlen));
    switch (addr.generic.sa_family) {
      case AF_INET: return ntohs(addr.inet4.sin_port);
      case AF_INET6: return ntohs(addr.inet6.sin6_port);
      default: return 0;
    }
  }
};

class UvLowLevelAsyncIoProvider final: public kj::LowLevelAsyncIoProvider {
public:
  UvLowLevelAsyncIoProvider(uv_loop_t* loop): eventPort(loop), waitScope(eventPort.getKjLoop()) {}

  inline kj::WaitScope& getWaitScope() { return waitScope; }

  kj::Own<kj::AsyncInputStream> wrapInputFd(int fd, uint flags = 0) override {
    return kj::heap<UvIoStream>(eventPort.getUvLoop(), fd, flags);
  }
  kj::Own<kj::AsyncOutputStream> wrapOutputFd(int fd, uint flags = 0) override {
    return kj::heap<UvIoStream>(eventPort.getUvLoop(), fd, flags);
  }
  kj::Own<kj::AsyncIoStream> wrapSocketFd(int fd, uint flags = 0) override {
    return kj::heap<UvIoStream>(eventPort.getUvLoop(), fd, flags);
  }
  kj::Promise<kj::Own<kj::AsyncIoStream>> wrapConnectingSocketFd(
      int fd, const struct sockaddr* addr, uint addrlen, uint flags = 0) override {
    // Unfortunately connect() doesn't fit the mold of KJ_NONBLOCKING_SYSCALL, since it indicates
    // non-blocking using EINPROGRESS.
    for (;;) {
      if (::connect(fd, addr, addrlen) < 0) {
        int error = errno;
        if (error == EINPROGRESS) {
          // Fine.
          break;
        } else if (error != EINTR) {
          KJ_FAIL_SYSCALL("connect()", error) { break; }
          return kj::Own<kj::AsyncIoStream>();
        }
      } else {
        // no error
        break;
      }
    }

    auto result = kj::heap<UvIoStream>(eventPort.getUvLoop(), fd, flags);
    auto connected = result->onWritable();
    return connected.then(kj::mvCapture(result,
        [fd](kj::Own<kj::AsyncIoStream>&& stream) {
          int err;
          socklen_t errlen = sizeof(err);
          KJ_SYSCALL(getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen));
          if (err != 0) {
            KJ_FAIL_SYSCALL("connect()", err) { break; }
          }
          return kj::mv(stream);
        }));
  }

#if CAPNP_VERSION < 7000
  kj::Own<kj::ConnectionReceiver> wrapListenSocketFd(int fd, uint flags = 0) override {
    return kj::heap<UvConnectionReceiver>(eventPort.getUvLoop(), fd, flags);
  }
#else
  kj::Own<kj::ConnectionReceiver> wrapListenSocketFd(int fd,
      kj::LowLevelAsyncIoProvider::NetworkFilter& filter, uint flags = 0) override {
    // TODO(soon): TODO(security): Actually use `filter`. Currently no API is exposed to set a
    //   filter so it's not important yet.
    return kj::heap<UvConnectionReceiver>(eventPort.getUvLoop(), fd, flags);
  }
#endif

  kj::Timer& getTimer() override {
    // TODO(soon):  Implement this.
    KJ_FAIL_ASSERT("Timers not implemented.");
  }

private:
  UvEventPort eventPort;
  kj::WaitScope waitScope;
};

// =======================================================================================
// KJ <-> v8 glue

// TODO(cleanup): V8 added this requirement that everything pass an Isolate. We should probably be
//   stringing it through rather than using v8::Isolate::GetCurrent() everywhere.
v8::Local<v8::String> newString(const char* str) {
  return v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), str, v8::NewStringType::kNormal).ToLocalChecked();
}
v8::Local<v8::String> newSymbol(const char* str) {
  return v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), str, v8::NewStringType::kInternalized).ToLocalChecked();
}
v8::Local<v8::Integer> newInt32(int i) {
  return v8::Int32::New(v8::Isolate::GetCurrent(), i);
}
void throwException(v8::Local<v8::Value> exception) {
  v8::Isolate::GetCurrent()->ThrowException(exception);
}

class EmptyHandle {
public:
  template <typename T>
  inline operator v8::Local<T>() const {
    return v8::Local<T>();
  }
};
static constexpr EmptyHandle emptyHandle = EmptyHandle();

kj::String typeName(const std::type_info& type) {
  int status;
  char* buf = abi::__cxa_demangle(type.name(), nullptr, nullptr, &status);
  kj::String result = kj::heapString(buf == nullptr ? type.name() : buf);
  free(buf);
  return kj::mv(result);
}

#define KJV8_TYPE_ERROR(name, type) \
  do {throwTypeError(#name, typeid(type), __func__, __FILE__, __LINE__); return;} while (false)

template <typename T>
class OwnHandle {
  // A v8 persistent handle with C++11 move semantics and RAII.

public:
  OwnHandle() = default;
  KJ_DISALLOW_COPY(OwnHandle);
  inline OwnHandle(const v8::Local<T>& other)
      : handle(v8::Isolate::GetCurrent(), other) {}
  inline OwnHandle(OwnHandle&& other) = default;

  inline OwnHandle& operator=(OwnHandle&& other) = default;
  inline OwnHandle& operator=(const v8::Local<T>& other) {
    handle.Reset(v8::Isolate::GetCurrent(), other);
    return *this;
  }

  inline bool operator==(decltype(nullptr)) { return handle.IsEmpty(); }
  inline bool operator!=(decltype(nullptr)) { return !handle.IsEmpty(); }
  inline T* operator->() const { return get().operator->(); }

  inline const v8::Local<T> get() const {
    return v8::Local<T>::New(v8::Isolate::GetCurrent(), handle);
  }

private:
  v8::Global<T> handle;
};

kj::String toKjString(v8::Local<v8::String> handle) {
  auto buf = kj::heapArray<char>(handle->Utf8Length(v8::Isolate::GetCurrent()) + 1);
  handle->WriteUtf8(v8::Isolate::GetCurrent(), buf.begin(), buf.size());
  buf[buf.size() - 1] = 0;
  return kj::String(kj::mv(buf));
}

kj::String toKjString(v8::Local<v8::Value> handle) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  return toKjString(Nan::To<v8::String>(handle).ToLocalChecked());
}

#define KJV8_STACK_STR(name, handle, sizeHint) \
  char name##_buf[sizeHint]; \
  kj::Array<char> name##_heap; \
  kj::StringPtr name; \
  { \
    v8::Local<v8::String> v8str = Nan::To<v8::String>(handle).ToLocalChecked(); \
    char* ptr; \
    size_t len = v8str->Utf8Length(v8::Isolate::GetCurrent()); \
    if (len < sizeHint) { \
      ptr = name##_buf; \
    } else { \
      name##_heap = kj::heapArray<char>(len + 1); \
      ptr = name##_heap.begin(); \
    } \
    v8str->WriteUtf8(v8::Isolate::GetCurrent(), ptr, len); \
    ptr[len] = '\0'; \
    name = kj::StringPtr(ptr, len); \
  }

v8::Local<v8::Value> toJsException(kj::Exception&& exception) {
  v8::Local<v8::Value> result = v8::Exception::Error(
      newString(exception.getDescription().cStr()));

  if (result->IsObject()) {
    v8::Object* obj = v8::Object::Cast(*result);

    obj->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("cppFile"), newString(exception.getFile())).Check();
    obj->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("line"), newInt32(exception.getLine())).Check();

    const char* type = "unknown";
    switch (exception.getType()) {
      case kj::Exception::Type::FAILED        : type = "failed"       ; break;
      case kj::Exception::Type::OVERLOADED    : type = "overloaded"   ; break;
      case kj::Exception::Type::DISCONNECTED  : type = "disconnected" ; break;
      case kj::Exception::Type::UNIMPLEMENTED : type = "unimplemented"; break;
    }
    obj->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("kjType"), newSymbol(type)).Check();
  } else {
    KJ_LOG(WARNING, "v8 exception is not an object?");
  }

  return result;
}

kj::Exception fromJsException(v8::Local<v8::Value> exception) {
  kj::Exception::Type type = kj::Exception::Type::FAILED;
  kj::String description;

  if (exception->IsObject()) {
    v8::HandleScope scope(v8::Isolate::GetCurrent());
    v8::Object* obj = v8::Object::Cast(*exception);
    v8::Local<v8::Value> value = obj->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("kjType")).ToLocalChecked();
    if (!value.IsEmpty() && !value->IsUndefined()) {
      auto name = toKjString(value);
      if (name == "overloaded") {
        type = kj::Exception::Type::OVERLOADED;
      } else if (name == "disconnected") {
        type = kj::Exception::Type::DISCONNECTED;
      } else if (name == "unimplemented") {
        type = kj::Exception::Type::UNIMPLEMENTED;
      }
    }

    v8::Local<v8::Value> stack = obj->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("stack")).ToLocalChecked();
    if (!stack.IsEmpty() && !stack->IsUndefined()) {
      description = toKjString(stack);
    } else {
      description = toKjString(exception);
    }
  }

  return kj::Exception(type, "(javascript)", 0, kj::mv(description));
}

EmptyHandle throwTypeError(kj::StringPtr name, const std::type_info& type,
                           const char* func, const char* file, int line) {
  kj::Exception exception(kj::Exception::Type::FAILED, file, line,
      kj::str(func, "(): Type error in parameter '", name, "'; expected type: ", typeName(type)));
  throwException(toJsException(kj::mv(exception)));
  return emptyHandle;
}

template <typename T>
struct LiftKj_;

template <typename T>
struct LiftKj_<v8::Local<T>> {
  template <typename Func>
  static void apply(const v8::FunctionCallbackInfo<v8::Value>& info, Func&& func) {
    KJ_IF_MAYBE(exception, kj::runCatchingExceptions([&]() {
      v8::HandleScope scope(v8::Isolate::GetCurrent());
      info.GetReturnValue().Set(func());
    })) {
      info.GetIsolate()->ThrowException(toJsException(kj::mv(*exception)));
    }
  }
};

template <>
struct LiftKj_<void> {
  template <typename Func>
  static void apply(const v8::FunctionCallbackInfo<v8::Value>& info, Func&& func) {
    KJ_IF_MAYBE(exception, kj::runCatchingExceptions([&]() {
      v8::HandleScope scope(v8::Isolate::GetCurrent());
      func();
      info.GetReturnValue().SetUndefined();
    })) {
      info.GetIsolate()->ThrowException(toJsException(kj::mv(*exception)));
    }
  }
};

template <typename Func>
void liftKj(const v8::FunctionCallbackInfo<v8::Value>& info, Func&& func) {
  // Lifts KJ code into V8 code: Catches exceptions and manages HandleScope. Converts the
  // function's return value into the appropriate V8 return.

  LiftKj_<decltype(func())>::apply(info, kj::fwd<Func>(func));
}

template <typename T>
struct Wrapped {
  T& value;
  v8::Local<v8::Object> wrapper;
};

class Wrapper {
  // Wraps C++ objects in v8 handles, assigning an appropriate type name and allowing for
  // type-checked unwrapping.

  template <typename T>
  struct WrappedObject {
    v8::Global<v8::Object> handle;
    T* ptr;

    WrappedObject(v8::Local<v8::Object> obj, T* ptr)
        : handle(v8::Isolate::GetCurrent(), obj),
          ptr(ptr) {
      handle.MarkIndependent();
      handle.SetWeak(this, &deleteCallback, v8::WeakCallbackType::kParameter);
    }

    ~WrappedObject() {
      // Since destructors might perform non-trivial operations, including calling back into
      // JavaScript, delay the destructor until the next turn of the event loop.
      T* ptrCopy = ptr;
      kj::evalLater([ptrCopy]() {
        delete ptrCopy;
      }).detach([](kj::Exception&& exception) {
        KJ_LOG(ERROR, exception);
      });
    }

    static void deleteCallback(const v8::WeakCallbackInfo<WrappedObject>& data) {
      delete reinterpret_cast<WrappedObject*>(data.GetParameter());
    }
  };

public:
  template <typename T>
  v8::Local<v8::Object> wrap(T* ptr) {
    v8::Local<v8::Object> obj = getFunctionTemplate<T>()
        ->GetFunction(v8::Isolate::GetCurrent()->GetCurrentContext()).ToLocalChecked()->NewInstance(v8::Isolate::GetCurrent()->GetCurrentContext())
        .ToLocalChecked();
    obj->SetAlignedPointerInInternalField(0, new WrappedObject<T>(obj, ptr));
    return obj;
  }

  template <typename T>
  v8::Local<v8::Object> wrapCopy(T&& value) {
    return wrap(new kj::Decay<T>(kj::fwd<T>(value)));
  }

  template <typename T>
  static kj::Maybe<T&> tryUnwrap(v8::Local<v8::Value> hdl) {
    if (!hdl->IsObject()) return nullptr;

    v8::Local<v8::Object> obj(v8::Local<v8::Object>::Cast(hdl));
    if (getFunctionTemplate<T>()->HasInstance(obj)) {
      return *reinterpret_cast<WrappedObject<T>*>(obj->GetAlignedPointerFromInternalField(0))->ptr;
    } else {
      v8::Isolate* isolate = v8::Isolate::GetCurrent();
      v8::Local<v8::Value> native;
      if (obj->GetPrivate(isolate->GetCurrentContext(),
              v8::Private::ForApi(isolate, newSymbol("capnp::native"))).ToLocal(&native) &&
          !native->IsUndefined()) {
        return tryUnwrap<T>(native);
      } else {
        return nullptr;
      }
    }
  }

  template <typename T>
  static kj::Maybe<T&> unwrap(v8::Local<v8::Value> hdl) {
    KJ_IF_MAYBE(result, tryUnwrap<T>(hdl)) {
      return *result;
    } else {
      auto message = kj::str("Type error (in Cap'n Proto glue).  Expected: ", typeid(T).name());
      throwException(v8::Exception::TypeError(newString(message.cStr())));
      return nullptr;
    }
  }

private:
  template <typename T>
  static void deleteAttachment(const v8::WeakCallbackInfo<void>& data) {
    delete reinterpret_cast<T*>(data.GetParameter());
  }

  template <typename T>
  static v8::Local<v8::FunctionTemplate> getFunctionTemplate() {
    // Get the singleton FunctionTemplate for some wrapped type T.

    // We allocate on the heap in order to prevent the destructor from running on shutdown, when
    // it will otherwise segfault.
    static OwnHandle<v8::FunctionTemplate>* tpl =
        new OwnHandle<v8::FunctionTemplate>(newFunctionTemplate<T>());

    return tpl->get();
  }

  template <typename T>
  static v8::Local<v8::FunctionTemplate> newFunctionTemplate() {
    const std::type_info& type = typeid(T);
    v8::Local<v8::FunctionTemplate> result = v8::FunctionTemplate::New(v8::Isolate::GetCurrent());
    result->InstanceTemplate()->SetInternalFieldCount(1);

    // TODO(someday):  Make stuff work with -fno-rtti?  node itself is compiled without RTTI...
    int status;
    char* buf = abi::__cxa_demangle(type.name(), nullptr, nullptr, &status);
    result->SetClassName(newString(buf == nullptr ? type.name() : buf));
    free(buf);

    return result;
  }
};

#define KJV8_UNWRAP(type, name, exp) \
  auto name##_maybe = Wrapper::tryUnwrap<type>(exp); \
  if (name##_maybe == nullptr) KJV8_TYPE_ERROR(name, type); \
  type& name KJ_UNUSED = KJ_ASSERT_NONNULL(name##_maybe)

kj::Maybe<kj::ArrayPtr<const byte>> unwrapBuffer(v8::Local<v8::Value> value) {
  if (!node::Buffer::HasInstance(value)) {
    return nullptr;
  }

  return kj::arrayPtr<const byte>(reinterpret_cast<byte*>(node::Buffer::Data(value)),
                                  node::Buffer::Length(value));
}

#define KJV8_UNWRAP_BUFFER(name, exp) \
  auto name##_maybe = unwrapBuffer(exp); \
  if (name##_maybe == nullptr) KJV8_TYPE_ERROR(name, kj::Array<byte>); \
  kj::ArrayPtr<const byte>& name = KJ_ASSERT_NONNULL(name##_maybe)

template <typename T>
void deleteArray(char*, void* hint) {
  delete reinterpret_cast<kj::Array<T>*>(hint);
}

template <typename T>
v8::Local<v8::Value> wrapBuffer(kj::Array<T>&& array) {
  char* data = reinterpret_cast<char*>(array.begin());
  size_t size = array.size() * sizeof(T);
  return node::Buffer::New(v8::Isolate::GetCurrent(), data, size, &deleteArray<T>,
                           new kj::Array<T>(kj::mv(array))).ToLocalChecked();
}

// =======================================================================================
// Cap'n Proto bindings

struct CapnpContext {
  // Shared context initialized when the module starts up.  This gets passed to each function as
  // the "data".

  UvLowLevelAsyncIoProvider llaiop;
  kj::Own<kj::AsyncIoProvider> aiop;
  capnp::SchemaParser parser;
  Wrapper wrapper;

  std::unordered_map<uint64_t, OwnHandle<v8::Value>> importedFiles;
  // Maps file IDs -> schema tree for that file.

  std::unordered_map<uint64_t, OwnHandle<v8::Object>> methodSets;
  // Maps interface type ID -> object mapping method names to method schemas for that type.

  kj::Vector<kj::Array<kj::String>> searchPaths;
  kj::Vector<kj::Array<kj::StringPtr>> searchPathPtrs;

  CapnpContext()
    : llaiop(uv_default_loop()),
      aiop(kj::newAsyncIoProvider(llaiop)) {}
};

void setNative(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // setNative(object, nativeHandle)
  //
  // Allows `object` to be passed into this module's functions where `nativeHandle` is expected,
  // without giving Javascript users of `object` access to `nativeHandle`.  This in particular
  // allows a capability wrapper defined in Javascript to be used to represent capabilities fields
  // passed to fromJs().

  if (args[0]->IsObject()) {
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    v8::Object::Cast(*args[0])->SetPrivate(
        isolate->GetCurrentContext(),
        v8::Private::ForApi(isolate, newSymbol("capnp::native")),
        args[1]);
  }
}

v8::Local<v8::Value> valueToJs(CapnpContext& context, capnp::DynamicValue::Reader value,
                                capnp::Type type, v8::Local<v8::Value> capConstructor);

v8::Local<v8::Value> schemaToObject(capnp::ParsedSchema schema, CapnpContext& context,
                                     v8::Local<v8::Value> wrappedContext) {
  auto proto = schema.getProto();
  if (proto.isConst()) {
    auto c = schema.asConst();
    return valueToJs(context, c, c.getType(), v8::Undefined(v8::Isolate::GetCurrent()));
  } else {
    auto result = context.wrapper.wrap(new capnp::Schema(schema));

    result->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("typeId"),
                // 64-bit values must be stringified to avoid losing precision.
                newString(kj::str(proto.getId()).cStr())).Check();

    for (auto nested: proto.getNestedNodes()) {
      kj::StringPtr name = nested.getName();
      result->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol(name.cStr()),
                  schemaToObject(schema.getNested(name), context, wrappedContext)).Check();
    }

    return result;
  }
}

void import(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // import(displayName, diskPath, searchPath) -> schema
  //
  // Parses the schema file at the given path.  See capnp::SchemaParser::parseDiskFile().
  //
  // The returned schema is an object with members corresponding to nested schemas.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_STACK_STR(displayName, args[0], 128);
  KJV8_STACK_STR(diskPath, args[1], 128);

  if (!args[2]->IsUndefined() && !args[2]->IsArray()) {
    args.GetIsolate()->ThrowException(
        v8::Exception::TypeError(newString("Search path must be array.")));
    return;
  }

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    kj::Array<kj::String> searchPath;
    kj::Array<kj::StringPtr> searchPathPtrs;
    if (!args[2]->IsUndefined()) {
      v8::Array* arr = v8::Array::Cast(*args[2]);
      searchPath = kj::heapArray<kj::String>(arr->Length());
      searchPathPtrs = kj::heapArray<kj::StringPtr>(searchPath.size());
      for (uint i: kj::indices(searchPath)) {
        searchPath[i] = toKjString(Nan::To<v8::String>(arr->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), i).ToLocalChecked()).ToLocalChecked());
        searchPathPtrs[i] = searchPath[i];
      }
    }

    capnp::ParsedSchema schema = context.parser.parseDiskFile(
        displayName, diskPath, searchPathPtrs);
    auto& slot = context.importedFiles[schema.getProto().getId()];
    if (slot == nullptr) {
      slot = schemaToObject(schema, context, args.Data());

      // We need to make sure our search paths are never deleted...
      context.searchPaths.add(kj::mv(searchPath));
      context.searchPathPtrs.add(kj::mv(searchPathPtrs));
    }
    return slot.get();
  });
}

void enumerateMethods(capnp::InterfaceSchema schema, v8::Local<v8::Object> methodMap,
                      CapnpContext& context, std::set<uint64_t>& seen) {
  auto proto = schema.getProto();
  if (seen.insert(proto.getId()).second) {
    for (auto superclass: schema.getSuperclasses()) {
      enumerateMethods(superclass, methodMap, context, seen);
    }

    auto methods = schema.getMethods();
    for (auto method: methods) {
      methodMap->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol(method.getProto().getName().cStr()),
                     context.wrapper.wrapCopy(method)).Check();
    }
  }
}

void methods(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // methods(schema) -> {name: method}
  //
  // Given an interface schema, returns the list of methods.  The returned list is memoized.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(capnp::Schema, schema, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    auto proto = schema.getProto();
    KJ_REQUIRE(proto.isInterface(), "not an interface type", proto.getDisplayName());

    auto& slot = context.methodSets[proto.getId()];
    if (slot == nullptr) {
      slot = v8::Object::New(v8::Isolate::GetCurrent());
      std::set<uint64_t> seen;
      enumerateMethods(schema.asInterface(), slot.get(), context, seen);
    }

    return slot.get();
  });
}

struct ClientRequest {
  kj::Maybe<capnp::Request<capnp::DynamicStruct, capnp::DynamicStruct>> request;
  // Becomes null when sent.
};

struct StructBuilder {
  capnp::MallocMessageBuilder message;
  capnp::DynamicStruct::Builder root;

  explicit StructBuilder(capnp::StructSchema schema)
      : root(message.getRoot<capnp::DynamicStruct>(schema)) {}
  explicit StructBuilder(capnp::DynamicStruct::Reader reader)
      : root(nullptr) {
    message.setRoot(reader);
    root = message.getRoot<capnp::DynamicStruct>(reader.getSchema());
  }
};

struct ServerResults: public kj::Refcounted {
  kj::Maybe<capnp::DynamicStruct::Builder> builder;
  // Becomes null when call returns.
};

kj::Maybe<capnp::DynamicStruct::Builder> unwrapBuilder(v8::Local<v8::Value> handle) {
  // We accept either StructBuilder or Request<DynamicStruct, DynamicStruct>.
  capnp::DynamicStruct::Builder builder;
  KJ_IF_MAYBE(request, Wrapper::tryUnwrap<ClientRequest>(handle)) {
    return request->request.map(
        [](capnp::Request<capnp::DynamicStruct, capnp::DynamicStruct>& inner)
        -> capnp::DynamicStruct::Builder {
      return inner;
    });
  } else KJ_IF_MAYBE(builder, Wrapper::tryUnwrap<StructBuilder>(handle)) {
    return builder->root;
  } else KJ_IF_MAYBE(results, Wrapper::tryUnwrap<kj::Own<ServerResults>>(handle)) {
    return results->get()->builder;
  } else {
    return nullptr;
  }
}

#define KJV8_UNWRAP_BUILDER(name, exp) \
  auto name##_maybe = unwrapBuilder(exp); \
  if (name##_maybe == nullptr) KJV8_TYPE_ERROR(name, capnp::DynamicStruct::Builder); \
  capnp::DynamicStruct::Builder& name = KJ_ASSERT_NONNULL(name##_maybe)

struct ClientResponse {
  kj::Maybe<capnp::Response<capnp::DynamicStruct>> response;
  // Becomes null when released.
};

struct StructReader {
  capnp::FlatArrayMessageReader message;
  capnp::DynamicStruct::Reader root;

  StructReader(kj::ArrayPtr<const capnp::word> data, capnp::StructSchema schema)
      : message(data), root(message.getRoot<capnp::DynamicStruct>(schema)) {}
};

struct FlatStructReader {
  kj::ArrayPtr<const capnp::word> segments[1];
  capnp::SegmentArrayMessageReader message;
  capnp::DynamicStruct::Reader root;

  FlatStructReader(kj::ArrayPtr<const capnp::word> data, capnp::StructSchema schema)
      : segments{data}, message(segments),
        root(message.getRoot<capnp::DynamicStruct>(schema)) {}
};

struct PackedStructReader {
  kj::ArrayInputStream inputStream;
  capnp::PackedMessageReader message;
  capnp::DynamicStruct::Reader root;

  PackedStructReader(kj::ArrayPtr<const byte> bytes, capnp::StructSchema schema)
      : inputStream(bytes), message(inputStream),
        root(message.getRoot<capnp::DynamicStruct>(schema)) {}
};

struct ServerRequest {
  kj::Own<kj::PromiseFulfiller<void>> fulfiller;
  // Fulfill to complete the call.  You must null out the pointers below, as well as
  // results->builder, when you do.

  kj::Maybe<capnp::CallContext<capnp::DynamicStruct, capnp::DynamicStruct>> context;
  // Becomes null when call returns.

  kj::Maybe<capnp::DynamicStruct::Reader> params;
  // Becomes null when params are released or call returns.

  kj::Maybe<kj::Own<ServerResults>> results;
  // Becomes non-null when getResults() is first called.  Subsequent calls return the same object.
};

kj::Maybe<capnp::DynamicStruct::Reader> unwrapReader(v8::Local<v8::Value> handle) {
  // We accept any builder as well as Response<DynamicStruct>.
  KJ_IF_MAYBE(response, Wrapper::tryUnwrap<ClientResponse>(handle)) {
    return response->response.map(
        [](capnp::Response<capnp::DynamicStruct>& inner)
        -> capnp::DynamicStruct::Reader {
      return inner;
    });
  } else KJ_IF_MAYBE(reader, Wrapper::tryUnwrap<StructReader>(handle)) {
    return reader->root;
  } else KJ_IF_MAYBE(reader, Wrapper::tryUnwrap<PackedStructReader>(handle)) {
    return reader->root;
  } else KJ_IF_MAYBE(reader, Wrapper::tryUnwrap<FlatStructReader>(handle)) {
    return reader->root;
  } else KJ_IF_MAYBE(request, Wrapper::tryUnwrap<ServerRequest>(handle)) {
    return request->params;
  } else KJ_IF_MAYBE(builder, unwrapBuilder(handle)) {
    return builder->asReader();
  } else {
    return nullptr;
  }
}

#define KJV8_UNWRAP_READER(name, exp) \
  auto name##_maybe = unwrapReader(exp); \
  if (name##_maybe == nullptr) KJV8_TYPE_ERROR(name, capnp::DynamicStruct::Reader); \
  capnp::DynamicStruct::Reader& name = KJ_ASSERT_NONNULL(name##_maybe)

void newBuilder(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // newBuilder(schema) -> builder
  //
  // Given a struct schema, returns a new builder for that type (backed by MallocMessageBuilder).

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(capnp::Schema, schema, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    KJ_REQUIRE(schema.getProto().isStruct(),
        "not a struct type", schema.getProto().getDisplayName());

    return context.wrapper.wrap(new StructBuilder(schema.asStruct()));
  });
}

void copyBuilder(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // copyBuilder(schema) -> builder
  //
  // Copy the contents of a builder or reader into a new builder.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP_READER(reader, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    return context.wrapper.wrap(new StructBuilder(reader));
  });
}

void structToString(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // structToString(builder OR reader) -> String
  //
  // Converts a struct builder or reader (or request or response) to a human-readable string
  // based on Cap'n Proto text format.

  KJV8_UNWRAP_READER(reader, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    return newString(kj::str(reader.getSchema().getProto().getDisplayName(), reader).cStr());
  });
}

// -----------------------------------------------------------------------------

struct FromJsConverter {
  CapnpContext& context;
  v8::Local<v8::Value> contextHandle;
  v8::Local<v8::Function> localCapType;

  capnp::DynamicCapability::Client fromLocalCap(
      capnp::InterfaceSchema schema, v8::Local<v8::Object> object);

  capnp::Orphan<capnp::DynamicValue> int64FromJs(v8::Local<v8::Value> js) {
    if (js->IsNumber()) {
      return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
    } else {
      KJV8_STACK_STR(text, js, 32);
      char* end;
      int64_t result = strtoll(text.cStr(), &end, 0);
      if (text.size() == 0 || *end != '\0') {
        return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      } else {
        return result;
      }
    }
  }

  capnp::Orphan<capnp::DynamicValue> uint64FromJs(v8::Local<v8::Value> js) {
    if (js->IsNumber()) {
      return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
    } else {
      KJV8_STACK_STR(text, js, 32);
      char* end;
      uint64_t result = strtoull(text.cStr(), &end, 0);
      if (text.size() == 0 || *end != '\0') {
        return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      } else {
        return result;
      }
    }
  }

  capnp::Orphan<capnp::DynamicValue> orphanFromJs(
      capnp::StructSchema::Field field, capnp::Orphanage orphanage,
      capnp::Type type, v8::Local<v8::Value> js) {
    switch (type.which()) {
      case capnp::schema::Type::VOID:
        // Accept any false-y value.
        if (!js->BooleanValue(v8::Isolate::GetCurrent())) {
          return capnp::VOID;
        }
        break;
      case capnp::schema::Type::BOOL:    return js->BooleanValue(v8::Isolate::GetCurrent());
      case capnp::schema::Type::INT8:    return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      case capnp::schema::Type::INT16:   return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      case capnp::schema::Type::INT32:   return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      case capnp::schema::Type::INT64:   return int64FromJs(js);
      case capnp::schema::Type::UINT8:   return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      case capnp::schema::Type::UINT16:  return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      case capnp::schema::Type::UINT32:  return js->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      case capnp::schema::Type::UINT64:  return uint64FromJs(js);
      case capnp::schema::Type::FLOAT32: return js->NumberValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      case capnp::schema::Type::FLOAT64: return js->NumberValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();
      case capnp::schema::Type::TEXT: {
        v8::HandleScope scope(v8::Isolate::GetCurrent());
        auto str = Nan::To<v8::String>(js).ToLocalChecked();
        capnp::Orphan<capnp::Text> orphan = orphanage.newOrphan<capnp::Text>(str->Utf8Length(v8::Isolate::GetCurrent()));
        str->WriteUtf8(v8::Isolate::GetCurrent(), orphan.get().begin(), orphan.get().size());
        return kj::mv(orphan);
      }
      case capnp::schema::Type::DATA:
        KJ_IF_MAYBE(buf, unwrapBuffer(js)) {
          return orphanage.newOrphanCopy(capnp::Data::Reader(*buf));
        }
        break;
      case capnp::schema::Type::LIST: {
        if (js->IsArray()) {
          v8::Array* jsArray = v8::Array::Cast(*js);
          auto schema = type.asList();
          auto elementType = schema.getElementType();
          auto orphan = orphanage.newOrphan(schema, jsArray->Length());
          auto builder = orphan.get();
          if (elementType.isStruct()) {
            // Struct lists can't adopt.
            bool error = false;
            for (uint i: kj::indices(builder)) {
              auto element = jsArray->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), i).ToLocalChecked();
              if (element->IsObject()) {
                if (!structFromJs(builder[i].as<capnp::DynamicStruct>(),
                                  v8::Object::Cast(*element))) {
                  return nullptr;
                }
              } else {
                error = true;
                break;
              }
            }
            if (error) break;
          } else {
            bool isPointerList = builder.as<capnp::AnyList>().getElementSize() ==
                                 capnp::ElementSize::POINTER;
            for (uint i: kj::indices(builder)) {
              auto jsElement = jsArray->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), i).ToLocalChecked();
              if (isPointerList && (jsElement->IsNull() || jsElement->IsUndefined())) {
                // Skip null element.
              } else {
                auto element = orphanFromJs(field, orphanage, elementType, jsElement);
                if (element.getType() == capnp::DynamicValue::UNKNOWN) {
                  return nullptr;
                }
                builder.adopt(i, kj::mv(element));
              }
            }
          }
          return kj::mv(orphan);
        }
        break;
      }
      case capnp::schema::Type::ENUM: {
        v8::HandleScope scope(v8::Isolate::GetCurrent());  // for string conversion
        KJV8_STACK_STR(name, js, 32);
        auto schema = type.asEnum();
        KJ_IF_MAYBE(enumerant, schema.findEnumerantByName(name)) {
          return capnp::DynamicEnum(*enumerant);
        } else if (js->IsUint32()) {
          return capnp::DynamicEnum(schema, js->Uint32Value(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked());
        }
        break;
      }
      case capnp::schema::Type::STRUCT: {
        KJ_IF_MAYBE(reader, unwrapReader(js)) {
          return orphanage.newOrphanCopy(*reader);
        } else if (js->IsObject()) {
          auto schema = type.asStruct();
          auto orphan = orphanage.newOrphan(schema);
          if (!structFromJs(orphan.get(), v8::Object::Cast(*js))) {
            return nullptr;
          }
          return kj::mv(orphan);
        }
        break;
      }
      case capnp::schema::Type::INTERFACE: {
        auto schema = type.asInterface();
        if (js->IsNull()) {
          auto cap = capnp::Capability::Client(nullptr)
              .castAs<capnp::DynamicCapability>(schema);
          return orphanage.newOrphanCopy(cap);
        } else KJ_IF_MAYBE(cap, Wrapper::tryUnwrap<capnp::DynamicCapability::Client>(js)) {
          return orphanage.newOrphanCopy(*cap);
        } else if (!localCapType.IsEmpty()) {
          v8::Local<v8::Value> arg = js;
          auto wrapped = localCapType->NewInstance(
              v8::Isolate::GetCurrent()->GetCurrentContext(), 1, &arg)
              .ToLocalChecked();
          if (!wrapped.IsEmpty()) {
            auto cap = fromLocalCap(schema, wrapped);
            return orphanage.newOrphanCopy(cap);
          }
        }
        break;
      }
      case capnp::schema::Type::ANY_POINTER:
        if (type.whichAnyPointerKind() == capnp::schema::Type::AnyPointer::Unconstrained::CAPABILITY) {
          if (js->IsNull()) {
            auto cap = capnp::Capability::Client(nullptr);
            capnp::DynamicCapability::Client dynamicCap(kj::mv(cap));
            return orphanage.newOrphanCopy(dynamicCap);
          } else KJ_IF_MAYBE(cap, Wrapper::tryUnwrap<capnp::DynamicCapability::Client>(js)) {
            return orphanage.newOrphanCopy(*cap);
          } else if (!localCapType.IsEmpty()) {
            v8::Local<v8::Value> arg = js;
            auto wrapped = localCapType->NewInstance(
                v8::Isolate::GetCurrent()->GetCurrentContext(), 1, &arg)
                .ToLocalChecked();
            if (!wrapped.IsEmpty()) {
              auto cap = fromLocalCap(capnp::Schema::from<capnp::Capability>(), wrapped);
              return orphanage.newOrphanCopy(cap);
            }
          }
        } else {
          KJ_IF_MAYBE(reader, unwrapReader(js)) {
            return orphanage.newOrphanCopy(*reader);
          } else KJ_IF_MAYBE(buffer, unwrapBuffer(js)) {
            kj::Array<capnp::word> scratch;
            kj::ArrayPtr<const capnp::word> words;
            if (reinterpret_cast<uintptr_t>(buffer->begin()) % sizeof(capnp::word) != 0) {
              // Array is not aligned.  We have to make a copy.  :(
              scratch = kj::heapArray<capnp::word>(buffer->size() / sizeof(capnp::word));
              memcpy(scratch.begin(), buffer->begin(), buffer->size());
              words = scratch;
            } else {
              // Yay, array is aligned.
              words = kj::arrayPtr(reinterpret_cast<const capnp::word*>(buffer->begin()),
                                   buffer->size() / sizeof(capnp::word));
            }
            capnp::FlatArrayMessageReader reader(words);
            return orphanage.newOrphanCopy(reader.getRoot<capnp::AnyPointer>());
          }
        }
        break;
    }

    throwException(v8::Exception::TypeError(newString(
        kj::str("Type error in field: ", field.getProto().getName()).cStr())));
    return nullptr;
  }

  bool fieldFromJs(capnp::DynamicStruct::Builder builder, capnp::StructSchema::Field field,
                   v8::Local<v8::Value> js) {
    if ((js->IsNull() || js->IsUndefined()) && !field.getType().isVoid()) {
      return true;
    }
    auto proto = field.getProto();
    switch (proto.which()) {
      case capnp::schema::Field::SLOT: {
        capnp::Orphan<capnp::DynamicValue> value = orphanFromJs(field,
            capnp::Orphanage::getForMessageContaining(builder), field.getType(), js);
        if (value.getType() == capnp::DynamicValue::UNKNOWN) {
          return false;
        }
        builder.adopt(field, kj::mv(value));
        return true;
      }

      case capnp::schema::Field::GROUP:
        if (js->IsObject()) {
          return structFromJs(builder.init(field).as<capnp::DynamicStruct>(),
                              v8::Object::Cast(*js));
        } else {
          throwException(v8::Exception::TypeError(newString(
              kj::str("Type error in field: ", proto.getName()).cStr())));
          return false;
        }
    }

    KJ_FAIL_ASSERT("Unimplemented field type (not slot or group).");
  }

  bool structFromJs(capnp::DynamicStruct::Builder builder, v8::Object* js) {
    v8::HandleScope scope(v8::Isolate::GetCurrent());
    auto schema = builder.getSchema();
  //  for (auto field: schema.getFields()) {
  //    kj::StringPtr name = field.getProto().getName();
  //    v8::Local<v8::Value> value = js->Get(newSymbol(name.begin(), name.size()));
  //    if (!value.IsEmpty() && !value->IsUndefined()) {
  //      fieldFromJs(builder, field, value);
  //    }
  //  }
    v8::Local<v8::Array> fieldNames = js->GetPropertyNames(v8::Isolate::GetCurrent()->GetCurrentContext()).ToLocalChecked();
    for (uint i: kj::range(0u, fieldNames->Length())) {
      auto jsName = fieldNames->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), i).ToLocalChecked();
      KJV8_STACK_STR(fieldName, jsName, 32);
      KJ_IF_MAYBE(field, schema.findFieldByName(fieldName)) {
        fieldFromJs(builder, *field, js->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), jsName).ToLocalChecked());
      } else {
        throwException(v8::Exception::TypeError(newString(
            kj::str("No field named: ", fieldName).cStr())));
        return false;
      }
    }
    return true;
  }
};

void fromJs(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // fromJs(builder, jso, LocalCap) -> void
  //
  // Copies the contents of a JS object into a struct builder.
  //
  // If `jso` is an array, it will be treated as an argument list ordered by ordinal.
  //
  // `LocalCap` is a constructor that takes a JS object as a parameter and produces a new object
  // that would be appropriate to pass to `newCap`.  Normally this means wrapping each method to
  // take an RPC request as its input.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP_BUILDER(builder, args[0]);
  v8::Local<v8::Value> jsValue = args[1];

  v8::Local<v8::Function> localCapType = emptyHandle;
  if (args[2]->IsFunction()) {
    localCapType = v8::Local<v8::Function>::Cast(args[2]);
  }

  liftKj(args, [&]() -> void {
    auto schema = builder.getSchema();

    FromJsConverter converter = { context, args.Data(), localCapType };

    if (jsValue->IsArray()) {
      v8::Array* array = v8::Array::Cast(*jsValue);
      auto fields = schema.getFields();
      uint length = kj::min(array->Length(), fields.size());

      for (uint i = 0; i < length; i++) {
        if (!converter.fieldFromJs(builder, fields[i], array->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), i).ToLocalChecked())) {
          break;
        }
      }
    } else if (jsValue->IsObject()) {
      converter.structFromJs(builder, v8::Object::Cast(*jsValue));
    } else {
      throwException(v8::Exception::TypeError(newString(
          "fromJs() requires an array or an object.")));
    }
  });
}

// -----------------------------------------------------------------------------

bool fieldToJs(CapnpContext& context, v8::Local<v8::Object> object,
               capnp::DynamicStruct::Reader reader, capnp::StructSchema::Field field,
               v8::Local<v8::Value> capConstructor);

v8::Local<v8::Value> valueToJs(CapnpContext& context, capnp::DynamicValue::Reader value,
                                capnp::Type type, v8::Local<v8::Value> capConstructor) {
  switch (value.getType()) {
    case capnp::DynamicValue::UNKNOWN:
      return v8::Undefined(v8::Isolate::GetCurrent());
    case capnp::DynamicValue::VOID:
      return v8::Null(v8::Isolate::GetCurrent());
    case capnp::DynamicValue::BOOL:
      return v8::Boolean::New(v8::Isolate::GetCurrent(), value.as<bool>());
    case capnp::DynamicValue::INT: {
      if (type.which() == capnp::schema::Type::INT64 ||
          type.which() == capnp::schema::Type::UINT64) {
        // 64-bit values must be stringified to avoid losing precision.
        return newString(kj::str(value.as<int64_t>()).cStr());
      } else {
        return v8::Integer::New(v8::Isolate::GetCurrent(), value.as<int32_t>());
      }
    }
    case capnp::DynamicValue::UINT: {
      if (type.which() == capnp::schema::Type::INT64 ||
          type.which() == capnp::schema::Type::UINT64) {
        // 64-bit values must be stringified to avoid losing precision.
        return newString(kj::str(value.as<uint64_t>()).cStr());
      } else {
        return v8::Integer::NewFromUnsigned(v8::Isolate::GetCurrent(), value.as<uint32_t>());
      }
    }
    case capnp::DynamicValue::FLOAT:
      return v8::Number::New(v8::Isolate::GetCurrent(), value.as<double>());
    case capnp::DynamicValue::TEXT: {
      capnp::Text::Reader text = value.as<capnp::Text>();
      return v8::String::NewFromUtf8(v8::Isolate::GetCurrent(), text.begin(),
                                     v8::NewStringType::kNormal, text.size()).ToLocalChecked();
    }
    case capnp::DynamicValue::DATA: {
      capnp::Data::Reader data = value.as<capnp::Data>();
      return node::Buffer::Copy(v8::Isolate::GetCurrent(),
          reinterpret_cast<const char*>(data.begin()), data.size()).ToLocalChecked();
    }
    case capnp::DynamicValue::LIST: {
      v8::EscapableHandleScope scope(v8::Isolate::GetCurrent());
      capnp::DynamicList::Reader list = value.as<capnp::DynamicList>();
      auto elementType = list.getSchema().getElementType();
      auto array = v8::Array::New(v8::Isolate::GetCurrent(), list.size());
      for (uint i: kj::indices(list)) {
        auto subValue = valueToJs(context, list[i], elementType, capConstructor);
        if (subValue.IsEmpty()) {
          return emptyHandle;
        }
        array->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), i, subValue).Check();
      }
      return scope.Escape(array);
    }
    case capnp::DynamicValue::ENUM: {
      auto enumValue = value.as<capnp::DynamicEnum>();
      KJ_IF_MAYBE(enumerant, enumValue.getEnumerant()) {
        return newSymbol(enumerant->getProto().getName().cStr());
      } else {
        return v8::Integer::NewFromUnsigned(v8::Isolate::GetCurrent(), enumValue.getRaw());
      }
    }
    case capnp::DynamicValue::STRUCT: {
      v8::EscapableHandleScope scope(v8::Isolate::GetCurrent());
      capnp::DynamicStruct::Reader reader = value.as<capnp::DynamicStruct>();
      auto object = v8::Object::New(v8::Isolate::GetCurrent());
      KJ_IF_MAYBE(field, reader.which()) {
        if (!fieldToJs(context, object, reader, *field, capConstructor)) {
          return emptyHandle;
        }
      }

      for (auto field: reader.getSchema().getNonUnionFields()) {
        if (reader.has(field)) {
          if (!fieldToJs(context, object, reader, field, capConstructor)) {
            return emptyHandle;
          }
        }
      }
      return scope.Escape(object);
    }
    case capnp::DynamicValue::CAPABILITY: {
      v8::EscapableHandleScope scope(v8::Isolate::GetCurrent());
      auto cap = value.as<capnp::DynamicCapability>();
      capnp::Schema schema = cap.getSchema();
      v8::Local<v8::Value> result = context.wrapper.wrapCopy(kj::mv(cap));
      if (capConstructor->IsFunction()) {
        v8::Function* func = v8::Function::Cast(*capConstructor);
        v8::Local<v8::Value> args[2] = { result, context.wrapper.wrapCopy(schema) };
        result = func->NewInstance(
            v8::Isolate::GetCurrent()->GetCurrentContext(), kj::size(args), args)
            .ToLocalChecked();
        if (result.IsEmpty()) {
          return emptyHandle;
        }
      }
      return scope.Escape(result);
    }
    case capnp::DynamicValue::ANY_POINTER: {
      if (type.whichAnyPointerKind() == capnp::schema::Type::AnyPointer::Unconstrained::CAPABILITY) {
        v8::EscapableHandleScope scope(v8::Isolate::GetCurrent());
        auto cap = value.as<capnp::AnyPointer>().getAs<capnp::Capability>();
        capnp::DynamicCapability::Client dynamicCap(kj::mv(cap));
        v8::Local<v8::Value> result = context.wrapper.wrapCopy(kj::mv(dynamicCap));
        if (capConstructor->IsFunction()) {
          v8::Function* func = v8::Function::Cast(*capConstructor);
          v8::Local<v8::Value> args[1] = { result };
          result = func->NewInstance(
            v8::Isolate::GetCurrent()->GetCurrentContext(), kj::size(args), args)
            .ToLocalChecked();
          if (result.IsEmpty()) {
            return emptyHandle;
          }
        }
        return scope.Escape(result);
      } else {
        capnp::MallocMessageBuilder message;
        message.setRoot(value.as<capnp::AnyPointer>());
        return wrapBuffer(capnp::messageToFlatArray(message));
      }
    }
  }

  KJ_FAIL_ASSERT("Unimplemented DynamicValue type.");
}

bool fieldToJs(CapnpContext& context, v8::Local<v8::Object> object,
               capnp::DynamicStruct::Reader reader, capnp::StructSchema::Field field,
               v8::Local<v8::Value> capConstructor) {
  auto proto = field.getProto();
  v8::Local<v8::Value> fieldValue;
  switch (proto.which()) {
    case capnp::schema::Field::SLOT:
      fieldValue = valueToJs(context, reader.get(field), field.getType(), capConstructor);
      goto setField;
    case capnp::schema::Field::GROUP:
      fieldValue = valueToJs(context, reader.get(field), field.getType(), capConstructor);
      goto setField;
  }

  KJ_FAIL_ASSERT("Unimplemented field type (not slot or group).");

setField:
  if (fieldValue.IsEmpty()) {
    return false;
  } else {
    object->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol(proto.getName().cStr()), fieldValue).Check();
    return true;
  }
}

void toJs(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // toJs(reader, CapType) -> object
  //
  // Given a struct reader, builds a JS object based on the contents.  If CapType is specified,
  // it is a constructor to use to build wrappers around capabilities in the object.  The
  // constructor will be passed the capability and its schema as parameters.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP_READER(reader, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    return valueToJs(context, reader, reader.getSchema(), args[1]);
  });
}

void toJsParams(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // toJsParams(reader, CapType) -> array
  //
  // Like toJs(), but interprets the input as a method parameter struct and produces a parameter
  // array from it.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP_READER(reader, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    auto schema = reader.getSchema();
    if (schema.getProto().getScopeId() == 0) {
      // This appears to be a parameter set.
      // (TODO(cleanup):  Detecting this by scope ID seems ugly, but currently there's no other
      // way.)

      auto fields = schema.getFields();
      auto result = v8::Array::New(v8::Isolate::GetCurrent(), fields.size());
      for (uint i: kj::indices(fields)) {
        result->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), i, valueToJs(context, reader.get(fields[i]), fields[i].getType(), args[1])).Check();
      }
      return result;
    } else {
      auto result = v8::Array::New(v8::Isolate::GetCurrent(), 1);
      result->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), 0, valueToJs(context, reader, reader.getSchema(), args[1])).Check();
      return result;
    }
  });
}

// -----------------------------------------------------------------------------

void expectedSizeFromPrefix(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // expectedSizeFromPrefix(buffer) -> int

  KJV8_UNWRAP(CapnpContext, context, args.Data());

  v8::Local<v8::Value> bufferHandle = args[0];
  KJV8_UNWRAP_BUFFER(buffer, bufferHandle);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    kj::ArrayPtr<const capnp::word> words;
    kj::Array<capnp::word> copy;
    if (reinterpret_cast<uintptr_t>(buffer.begin()) % sizeof(capnp::word) != 0) {
      // Array is not aligned.  We have to make a copy.  :(
      copy = kj::heapArray<capnp::word>(buffer.size() / sizeof(capnp::word));
      memcpy(copy.begin(), buffer.begin(), copy.asBytes().size());
    } else {
      // Yay, array is aligned.
      words = kj::arrayPtr(reinterpret_cast<const capnp::word*>(buffer.begin()),
                           buffer.size() / sizeof(capnp::word));
    }

    return v8::Integer::New(args.GetIsolate(),
        capnp::expectedSizeInWordsFromPrefix(words) * sizeof(capnp::word));
  });
}

void fromBytes(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // fromBytes(buffer, schema, options) -> reader

  KJV8_UNWRAP(CapnpContext, context, args.Data());

  v8::Local<v8::Value> bufferHandle = args[0];
  KJV8_UNWRAP_BUFFER(buffer, bufferHandle);

  KJV8_UNWRAP(capnp::Schema, schema, args[1]);
  if (!schema.getProto().isStruct()) {
    KJV8_TYPE_ERROR(schema, capnp::StructSchema);
  }

  if (!args[2]->IsObject()) {
    KJV8_TYPE_ERROR(obj, v8::Object);
  }

  return liftKj(args, [&]() -> v8::Local<v8::Value> {
    auto options = args[2].As<v8::Object>();
    bool packed = options->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("packed")).ToLocalChecked()->BooleanValue(v8::Isolate::GetCurrent());
    bool flat = options->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("flat")).ToLocalChecked()->BooleanValue(v8::Isolate::GetCurrent());

    v8::Local<v8::Object> wrapper;

    if (packed) {
      if (flat) {
        auto bytes = kj::arrayPtr(buffer.begin(), buffer.size());
        auto words = kj::heapArray<capnp::word>(capnp::computeUnpackedSizeInWords(bytes));
        kj::ArrayInputStream input(bytes);
        capnp::_::PackedInputStream unpacker(input);
        unpacker.read(words.asBytes().begin(), words.asBytes().size());
        wrapper = context.wrapper.wrap(new FlatStructReader(words, schema.asStruct()));
        bufferHandle = context.wrapper.wrapCopy(kj::mv(words));
      } else {
        wrapper = context.wrapper.wrap(new PackedStructReader(
            kj::arrayPtr(buffer.begin(), buffer.size()), schema.asStruct()));
      }
    } else {
      kj::ArrayPtr<const capnp::word> words;
      if (reinterpret_cast<uintptr_t>(buffer.begin()) % sizeof(capnp::word) != 0) {
        // Array is not aligned.  We have to make a copy.  :(
        auto array = kj::heapArray<capnp::word>(buffer.size() / sizeof(capnp::word));
        memcpy(array.begin(), buffer.begin(), array.asBytes().size());
        words = array;
        bufferHandle = context.wrapper.wrapCopy(kj::mv(array));
      } else {
        // Yay, array is aligned.
        words = kj::arrayPtr(reinterpret_cast<const capnp::word*>(buffer.begin()),
                             buffer.size() / sizeof(capnp::word));
      }

      if (flat) {
        wrapper = context.wrapper.wrap(new FlatStructReader(words, schema.asStruct()));
      } else {
        wrapper = context.wrapper.wrap(new StructReader(words, schema.asStruct()));
      }
    }

    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    wrapper->SetPrivate(
        isolate->GetCurrentContext(),
        v8::Private::ForApi(isolate, newSymbol("capnp::buffer")),
        bufferHandle);
    return wrapper;
  });
}

void toBytes(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // toBytes(builder, options) -> buffer

  KJV8_UNWRAP(StructBuilder, builder, args[0]);
  if (!args[1]->IsObject()) {
    KJV8_TYPE_ERROR(obj, v8::Object);
  }

  return liftKj(args, [&]() -> v8::Local<v8::Value> {
    auto options = args[1].As<v8::Object>();
    bool packed = options->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("packed")).ToLocalChecked()->BooleanValue(v8::Isolate::GetCurrent());
    bool flat = options->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("flat")).ToLocalChecked()->BooleanValue(v8::Isolate::GetCurrent());

    if (flat) {
      // Write whole message to flat array.
      auto root = builder.root.asReader();
      auto words = kj::heapArray<capnp::word>(root.totalSize().wordCount + 1);
      memset(words.asBytes().begin(), 0, words.asBytes().size());
      capnp::copyToUnchecked(root, words);

      if (packed) {
        kj::VectorOutputStream output;
        capnp::_::PackedOutputStream packer(output);
        packer.write(words.asBytes().begin(), words.asBytes().size());
        return wrapBuffer(kj::heapArray(output.getArray()));
      } else {
        return wrapBuffer(kj::mv(words));
      }
    } else if (packed) {
      kj::VectorOutputStream output;
      capnp::writePackedMessage(output, builder.message);
      auto packedMessage = heapArray(output.getArray());
      return wrapBuffer(kj::mv(packedMessage));
    } else {
      return wrapBuffer(capnp::messageToFlatArray(builder.message));
    }
  });
}

// -----------------------------------------------------------------------------

class RpcConnection: public kj::Refcounted {
  // A two-party RPC connection.

public:
  RpcConnection(kj::Own<kj::AsyncIoStream>&& streamParam,
                kj::Maybe<capnp::Capability::Client> bootstrap)
      : stream(kj::mv(streamParam)),
        network(*stream, capnp::rpc::twoparty::Side::CLIENT),
        rpcSystem(network, bootstrap) {}

  capnp::Capability::Client import(kj::StringPtr ref) {
    capnp::MallocMessageBuilder builder;
    auto hostIdOrphan = builder.getOrphanage().newOrphan<capnp::rpc::twoparty::SturdyRefHostId>();
    auto hostId = hostIdOrphan.get();
    hostId.setSide(capnp::rpc::twoparty::Side::SERVER);
    auto objectId = builder.getRoot<capnp::AnyPointer>();
    objectId.setAs<capnp::Text>(ref);

    return rpcSystem.restore(hostId, objectId);
  }

  capnp::Capability::Client importDefault() {
    capnp::MallocMessageBuilder builder;
    auto hostId = builder.initRoot<capnp::rpc::twoparty::SturdyRefHostId>();
    hostId.setSide(capnp::rpc::twoparty::Side::SERVER);

    return rpcSystem.bootstrap(hostId);
  }

  kj::Own<RpcConnection> addRef() {
    return kj::addRef(*this);
  }

  void close() {
    stream->shutdownWrite();
  }

private:
  kj::Own<kj::AsyncIoStream> stream;
  capnp::TwoPartyVatNetwork network;
  capnp::RpcSystem<capnp::rpc::twoparty::SturdyRefHostId> rpcSystem;
};

struct ConnectionWrapper {
  kj::ForkedPromise<kj::Own<RpcConnection>> promise;
};

void connect(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // connect(addr, bootstrap) -> connection
  //
  // Connect to the given address using the two-party protocol, exporting a bootstrap capability if
  // given one.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_STACK_STR(address, args[0], 64);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    kj::Maybe<capnp::Capability::Client> bootstrap =
        Wrapper::tryUnwrap<capnp::DynamicCapability::Client>(args[1]);

    auto promise = context.aiop->getNetwork().parseAddress(address)
        .then([](kj::Own<kj::NetworkAddress>&& addr) {
      return addr->connect();
    }).then(kj::mvCapture(kj::mv(bootstrap),
        [](kj::Maybe<capnp::Capability::Client>&& bootstrap,
           kj::Own<kj::AsyncIoStream>&& stream) {
      return kj::refcounted<RpcConnection>(kj::mv(stream), bootstrap);
    }));

    return context.wrapper.wrapCopy(ConnectionWrapper { promise.fork() });
  });
}

void connectUnixFd(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // connectUnixFd(fd, bootstrap) -> connection
  //
  // Given the FD of a Unix domain socket, form a connection to the server at the other end by
  // sending it an FD. Specifically, create a new socketpair, and send one end of the pair over
  // the existing socket.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  int fd = args[0]->IntegerValue(v8::Isolate::GetCurrent()->GetCurrentContext()).ToChecked();

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    int fdPair[2];
    KJ_SYSCALL(socketpair(AF_UNIX, SOCK_STREAM, 0, fdPair));
    kj::AutoCloseFd clientEnd(fdPair[0]);
    kj::AutoCloseFd serverEnd(fdPair[1]);

    struct msghdr msg;
    struct iovec iov;
    union {
      struct cmsghdr cmsg;
      char cmsgSpace[CMSG_LEN(sizeof(int))];
    };
    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(cmsgSpace, 0, sizeof(cmsgSpace));

    char c = 0;
    iov.iov_base = &c;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof(cmsgSpace);

    cmsg.cmsg_len = sizeof(cmsgSpace);
    cmsg.cmsg_level = SOL_SOCKET;
    cmsg.cmsg_type = SCM_RIGHTS;
    *reinterpret_cast<int*>(CMSG_DATA(&cmsg)) = serverEnd;

    // TODO(someday): This could fail with EAGAIN (or block, if the FD is not in non-blocking mode)
    //   if somehow the client is forming connections faster than the server can accept them. For
    //   now I don't care enough to handle this.
    KJ_SYSCALL(sendmsg(fd, &msg, 0));
    serverEnd = nullptr;

    kj::Maybe<capnp::Capability::Client> bootstrap =
        Wrapper::tryUnwrap<capnp::DynamicCapability::Client>(args[1]);

    auto stream = context.llaiop.LowLevelAsyncIoProvider::wrapSocketFd(kj::mv(clientEnd));
    kj::Promise<kj::Own<RpcConnection>> promise =
        kj::refcounted<RpcConnection>(kj::mv(stream), bootstrap);

    return context.wrapper.wrapCopy(ConnectionWrapper { promise.fork() });
  });
}

void disconnect(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // disconnect(connection)
  //
  // Shuts down the connection.

  KJV8_UNWRAP(ConnectionWrapper, connectionWrapper, args[0]);

  liftKj(args, [&]() -> void {
    connectionWrapper.promise.addBranch().then([](kj::Own<RpcConnection>&& connection) {
      connection->close();
    }).detach([](kj::Exception&& e) {
      KJ_LOG(ERROR, e);
    });
  });
}

void restore(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // restore(connection, objectId, schema) -> cap
  //
  // Restore a SturdyRef from the other end of a two-party connection.  objectId may be a string,
  // reader, or builder.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(ConnectionWrapper, connectionWrapper, args[0]);
  bool isNullRef = args[1]->IsNull();
  auto ref = toKjString(args[1]);  // TODO(soon):  Allow struct reader.
  KJV8_UNWRAP(capnp::Schema, schema, args[2]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    KJ_REQUIRE(schema.getProto().isInterface(),
        "not an interface type", schema.getProto().getDisplayName());

    capnp::Capability::Client client = connectionWrapper.promise.addBranch()
        .then(kj::mvCapture(ref,[isNullRef](kj::String&& ref, kj::Own<RpcConnection>&& connection) {
      return isNullRef ? connection->importDefault() : connection->import(ref);
    }));

    return context.wrapper.wrapCopy(client.castAs<capnp::DynamicCapability>(schema.asInterface()));
  });
}

void castAs(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // castAs(cap, schema) -> cap
  //
  // Reinterpret the capability as implementing a different interface.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(capnp::DynamicCapability::Client, cap, args[0]);
  KJV8_UNWRAP(capnp::Schema, schema, args[1]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    KJ_REQUIRE(schema.getProto().isInterface(),
        "not an interface type", schema.getProto().getDisplayName());
    return context.wrapper.wrapCopy(cap.castAs<capnp::DynamicCapability>(schema.asInterface()));
  });
}

void schemaFor(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // schemaFor(cap) -> schema
  //
  // Get the schema for a capability.  Unlike with import(), the returned object does NOT contain
  // nested schemas, though it can be passed to methods() to obtain a method list.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(capnp::DynamicCapability::Client, cap, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    return context.wrapper.wrapCopy(capnp::Schema(cap.getSchema()));
  });
}

void closeCap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // close(cap) -> void
  //
  // Close the capability, discarding the underlying reference.  Doing this explicitly (rather than
  // waiting for GC) allows the other end to more quickly receive notification that it can clean up
  // the object.

  KJV8_UNWRAP(capnp::DynamicCapability::Client, cap, args[0]);

  liftKj(args, [&]() -> void {
    // Overwrite with a disconnected cap.
    cap = capnp::Capability::Client(
        capnp::newBrokenCap(KJ_EXCEPTION(DISCONNECTED, "Capability has been closed.")))
        .castAs<capnp::DynamicCapability>(cap.getSchema());
  });
}

void release(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // release(response) -> void
  //
  // Release a client-side response object, thus releasing all contained capabilities. Any further
  // attempt to use the response (e.g. with toJs()) will throw a type error.

  KJV8_UNWRAP(ClientResponse, response, args[0]);

  liftKj(args, [&]() -> void {
    response.response = nullptr;
  });
}

void dupCap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // dup(cap) -> cap
  //
  // Return a new reference to the given cap which must be separately close()ed.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(capnp::DynamicCapability::Client, cap, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    return context.wrapper.wrapCopy(cap);
  });
}

void dup2Cap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // dup2(srcCap, dstCap)
  //
  // Overwrite dstCap so that it points to a new reference to srcCap.  The old dstCap is closed.
  // This function is provided mainly so that after a call completes, the pipeline caps can be
  // replaced with their resolved versions, to avoid the need to make the application close()
  // the pipelined caps separately from the final versions.

  KJV8_UNWRAP(capnp::DynamicCapability::Client, srcCap, args[0]);
  KJV8_UNWRAP(capnp::DynamicCapability::Client, dstCap, args[1]);

  liftKj(args, [&]() -> void {
    dstCap = srcCap;
  });
}

void request(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // request(cap, method) -> request (a builder)
  //
  // Start a new request.  Returns the request builder, which can also be passed to send().

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(capnp::DynamicCapability::Client, cap, args[0]);
  KJV8_UNWRAP(capnp::InterfaceSchema::Method, method, args[1]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    return context.wrapper.wrapCopy(ClientRequest { cap.newRequest(method) });
  });
}

void pipelineToJs(CapnpContext& context, capnp::DynamicStruct::Pipeline&& pipeline,
                  v8::Local<v8::Object> js, v8::Local<v8::Value> capConstructor);

v8::Local<v8::Object> pipelineStructFieldToJs(CapnpContext& context,
                                               capnp::DynamicStruct::Pipeline& pipeline,
                                               capnp::StructSchema::Field field,
                                               v8::Local<v8::Value> capConstructor) {
  v8::Local<v8::Object> fieldValue = v8::Object::New(v8::Isolate::GetCurrent());
  pipelineToJs(context, pipeline.get(field).releaseAs<capnp::DynamicStruct>(),
               fieldValue, capConstructor);
  return fieldValue;
}

void pipelineToJs(CapnpContext& context, capnp::DynamicStruct::Pipeline&& pipeline,
                  v8::Local<v8::Object> js, v8::Local<v8::Value> capConstructor) {
  v8::HandleScope scope(v8::Isolate::GetCurrent());
  capnp::StructSchema schema = pipeline.getSchema();

  for (capnp::StructSchema::Field field: schema.getNonUnionFields()) {
    auto proto = field.getProto();
    v8::Local<v8::Object> fieldValue;

    switch (proto.which()) {
      case capnp::schema::Field::SLOT: {
        auto type = field.getType();
        switch (type.which()) {
          case capnp::schema::Type::STRUCT:
            fieldValue = pipelineStructFieldToJs(context, pipeline, field, capConstructor);
            break;
          case capnp::schema::Type::ANY_POINTER:
            if (type.whichAnyPointerKind() !=
                capnp::schema::Type::AnyPointer::Unconstrained::CAPABILITY) {
              continue;
            }
            // fallthrough
          case capnp::schema::Type::INTERFACE: {
            auto cap = pipeline.get(field).releaseAs<capnp::DynamicCapability>();
            capnp::Schema capSchema = cap.getSchema();
            fieldValue = context.wrapper.wrapCopy(kj::mv(cap));
            if (!capConstructor->IsUndefined() && capConstructor->IsFunction()) {
              v8::Function* func = v8::Function::Cast(*capConstructor);
              v8::Local<v8::Value> args[2] = { fieldValue,
                  context.wrapper.wrapCopy(kj::mv(capSchema)) };
              fieldValue = func->NewInstance(
                  v8::Isolate::GetCurrent()->GetCurrentContext(), kj::size(args), args)
                  .ToLocalChecked();
            }
            break;
          }
          default:
            continue;
        }
        break;
      }

      case capnp::schema::Field::GROUP:
        fieldValue = pipelineStructFieldToJs(context, pipeline, field, capConstructor);
        break;

      default:
        continue;
    }

    KJ_ASSERT(!fieldValue.IsEmpty());
    js->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol(proto.getName().cStr()), fieldValue).Check();
  }
}

struct Canceler: public kj::Refcounted {
  kj::Own<kj::PromiseFulfiller<capnp::Response<capnp::DynamicStruct>>> fulfiller;
};

void send(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // send(request, callback, errorCallback, CapType) -> pipeline tree
  //
  // Send a request and call the callback when done, passing the final result.
  //
  // Calls `errorCallback` if there is an error, passing it an object describing the KJ exception
  // (this is not a JS Error object!).
  //
  // Returns an object tree representing all of the promise's pipelined capabilities.  Be careful:
  // each of these capabilities needs to be close()ed.
  //
  // CapType is the constructor for a capability wrapper; see toJs().

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(ClientRequest, request, args[0]);

  if (!args[1]->IsFunction() || !args[2]->IsFunction()) {
    throwException(v8::Exception::TypeError(newString("Callbacks must be functions.")));
    return;
  }

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    OwnHandle<v8::Function> callback = v8::Local<v8::Function>::Cast(args[1]);
    OwnHandle<v8::Function> errorCallback = v8::Local<v8::Function>::Cast(args[2]);

    auto promise = KJ_REQUIRE_NONNULL(request.request, "Request already sent.").send();
    request.request = nullptr;

    auto cancelerPaf = kj::newPromiseAndFulfiller<capnp::Response<capnp::DynamicStruct>>();

    auto canceler = kj::refcounted<Canceler>();
    canceler->fulfiller = kj::mv(cancelerPaf.fulfiller);

    v8::Local<v8::Object> result = context.wrapper.wrapCopy(kj::addRef(*canceler));

    // Wait for results and call the callback.  Note that we can safely capture `context` by
    // reference because if the context is destroyed, the event loop will stop running.
    promise.exclusiveJoin(kj::mv(cancelerPaf.promise))
        .attach(kj::mv(canceler))  // Prevent cancellation from GC.
        .then(kj::mvCapture(callback,
          [&context](OwnHandle<v8::Function>&& callback,
                     capnp::Response<capnp::DynamicStruct>&& response) {
      v8::HandleScope scope(v8::Isolate::GetCurrent());
      v8::Local<v8::Value> args[1] = {
        context.wrapper.wrapCopy(ClientResponse { kj::mv(response) })
      };
      // TODO(cleanup):  Call() demands an Object parameter but `undefined` is not an object.  So
      //   we pass an empty object.  Can we do better?
      node::MakeCallback(scope.GetIsolate(), v8::Object::New(scope.GetIsolate()),
                         callback.get(), 1, args);
    })).detach(kj::mvCapture(errorCallback,
          [&context](OwnHandle<v8::Function>&& errorCallback,
                     kj::Exception&& exception) {
      v8::HandleScope scope(v8::Isolate::GetCurrent());
      v8::Local<v8::Value> args[1] = { toJsException(kj::mv(exception)) };
      node::MakeCallback(scope.GetIsolate(), v8::Object::New(scope.GetIsolate()),
                         errorCallback.get(), 1, args);
    }));

    pipelineToJs(context, kj::mv(promise), result, args[3]);
    return result;
  });
}

void cancel(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // cancel(pipeline) -> void
  //
  // Request cancellation of the given RPC.  If the RPC hasn't completed yet, it will be canceled
  // and errorCallback will be called with an appropriate error.  Note that `callback` could still
  // be called after cancel(), if it was already queued in the event loop at time of cancellation.

  KJV8_UNWRAP(kj::Own<Canceler>, canceler, args[0]);

  liftKj(args, [&]() -> void {
    canceler->fulfiller->reject(KJ_EXCEPTION(FAILED, "request canceled by caller"));
  });
}

// -----------------------------------------------------------------------------
// Local caps

class LocalCap final: public capnp::DynamicCapability::Server {
public:
  LocalCap(capnp::InterfaceSchema schema, v8::Local<v8::Object> object,
           CapnpContext& capnpContext, v8::Local<v8::Value> capnpContextHandle)
      : capnp::DynamicCapability::Server(schema),
        object(object), capnpContext(capnpContext), capnpContextHandle(capnpContextHandle) {}

  ~LocalCap() {
    // Call the object's close() method if it has one, so that it can react to the handle being
    // dropped.

    v8::HandleScope scope(v8::Isolate::GetCurrent());

    auto jsMethod = object->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("close")).ToLocalChecked();
    if (jsMethod->IsFunction()) {
      auto func = v8::Local<v8::Function>::Cast(jsMethod);
      node::MakeCallback(scope.GetIsolate(), object.get(), func, 0, nullptr);
    }
  }

  kj::Promise<void> call(capnp::InterfaceSchema::Method method,
      capnp::CallContext<capnp::DynamicStruct, capnp::DynamicStruct> context) override {
    v8::HandleScope scope(v8::Isolate::GetCurrent());

    auto jsMethod = object->Get(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol(method.getProto().getName().cStr())).ToLocalChecked();

    if (!jsMethod->IsFunction()) {
      auto name = method.getProto().getName();
      KJ_FAIL_ASSERT("Method not implemented.", name) { break; }
      return kj::READY_NOW;
    }
    auto func = v8::Local<v8::Function>::Cast(jsMethod);

    auto paf = kj::newPromiseAndFulfiller<void>();

    ServerRequest request;
    request.fulfiller = kj::mv(paf.fulfiller);
    request.context = context;
    request.params = context.getParams();

    v8::Local<v8::Value> arg = capnpContext.wrapper.wrapCopy(kj::mv(request));
    node::MakeCallback(scope.GetIsolate(), object.get(), func, 1, &arg);
    return kj::mv(paf.promise);
  }

private:
  OwnHandle<v8::Object> object;
  CapnpContext& capnpContext;
  OwnHandle<v8::Value> capnpContextHandle;
};

capnp::DynamicCapability::Client FromJsConverter::fromLocalCap(
    capnp::InterfaceSchema schema, v8::Local<v8::Object> object) {
  return kj::heap<LocalCap>(schema, object, context, contextHandle);
}

void newCap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // newCap(schema, obj) -> cap
  //
  // Creates a capability hosted locally.  `obj` is an object mapping method names to methods.
  // Each method takes a ServerRequest (which acts as a Reader, but also has additional methods)
  // as its parameter, and the result is ignored.
  //
  // If `obj` is actually a native cap, this method just returns it.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(capnp::Schema, schema, args[0]);
  if (!schema.getProto().isInterface()) {
    KJV8_TYPE_ERROR(schema, capnp::InterfaceSchema);
  }
  if (!args[1]->IsObject()) {
    KJV8_TYPE_ERROR(obj, v8::Object);
  }

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    return context.wrapper.wrapCopy(capnp::DynamicCapability::Client(
        kj::heap<LocalCap>(schema.asInterface(),
                           v8::Local<v8::Object>::Cast(args[1]),
                           context, args.Data())));
  });
}

void newPromisedCap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // newPromisedCap(schema) -> { cap, fulfiller }
  //
  // Creates a capability whose endpoint is not yet known. Calls are held in a queue until
  // `fulfiller` is fulfilled via `fulfillPromisedCap` or `rejectPromisedCap`.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(capnp::Schema, schema, args[0]);
  if (!schema.getProto().isInterface()) {
    KJV8_TYPE_ERROR(schema, capnp::InterfaceSchema);
  }

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    auto paf = kj::newPromiseAndFulfiller<capnp::Capability::Client>();

    v8::Local<v8::Object> result = v8::Object::New(v8::Isolate::GetCurrent());
    result->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("cap"),
        context.wrapper.wrapCopy(
            capnp::Capability::Client(kj::mv(paf.promise))
                .castAs<capnp::DynamicCapability>(schema.asInterface()))).Check();
    result->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol("fulfiller"),
        context.wrapper.wrapCopy(kj::mv(paf.fulfiller))).Check();
    return result;
  });
}

void fulfillPromisedCap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // fulfillPromisedCap(fulfiller, cap)
  //
  // Fulfills a promise created by a previous call to `newPromisedCap()`.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(kj::Own<kj::PromiseFulfiller<capnp::Capability::Client>>, fulfiller, args[0]);
  KJV8_UNWRAP(capnp::DynamicCapability::Client, cap, args[1]);

  liftKj(args, [&]() -> void {
    auto schema = cap.getSchema();

    fulfiller->fulfill(kj::mv(cap));

    // Avoid segfault if capability is called again.
    cap = capnp::Capability::Client(
        capnp::newBrokenCap(KJ_EXCEPTION(DISCONNECTED,
            "Capability was used to resolve a promise capability and so has been closed.")))
        .castAs<capnp::DynamicCapability>(schema);
  });
}

void rejectPromisedCap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // rejectPromisedCap(fulfiller, error)
  //
  // Rejects a promise created by a previous call to `newPromisedCap()`.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(kj::Own<kj::PromiseFulfiller<capnp::Capability::Client>>, fulfiller, args[0]);

  liftKj(args, [&]() -> void {
    fulfiller->reject(fromJsException(args[1]));
  });
}

void isCap(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // isCap(value) -> boolean
  //
  // If `value` is a capability, return true.

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    return v8::Boolean::New(v8::Isolate::GetCurrent(),
        Wrapper::tryUnwrap<capnp::DynamicCapability::Client>(args[0]) != nullptr);
  });
}

void releaseParams(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // releaseParams(serverRequest) -> void
  //
  // Release the parameter strurct for the request.  The parameters will appear to be an empty
  // struct if accessed after this call.

  KJV8_UNWRAP(ServerRequest, request, args[0]);

  liftKj(args, [&]() -> void {
    KJ_IF_MAYBE(callContext, request.context) {
      request.params = nullptr;
      callContext->releaseParams();
    }
  });
}

void getResults(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // getResults(serverRequest) -> builder
  //
  // Get the results builder for the giver request object.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP(ServerRequest, request, args[0]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    kj::Own<ServerResults> results;
    KJ_IF_MAYBE(existing, request.results) {
      results = kj::addRef(**existing);
    } else {
      results = kj::refcounted<ServerResults>();
      request.results = kj::addRef(*results);
      KJ_IF_MAYBE(callContext, request.context) {
        results->builder = callContext->getResults();
      }
    }
    return context.wrapper.wrapCopy(kj::mv(results));
  });
}

void return_(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // return_(serverRequest) -> void
  //
  // Completes the given request.  getResults() should be used to fill in the results before
  // calling this.  The params and results builders are invalidated after this is called.

  KJV8_UNWRAP(ServerRequest, request, args[0]);

  liftKj(args, [&]() -> void {
    request.context = nullptr;
    request.params = nullptr;
    KJ_IF_MAYBE(results, request.results) {
      results->get()->builder = nullptr;
    }
    request.fulfiller->fulfill();
  });
}

void throw_(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // throw_(serverRequest, error) -> void
  //
  // Fail the request with an error (should be a Javascript `Error` object).  The params and
  // results builders are invalidated after this is called.

  KJV8_UNWRAP(ServerRequest, request, args[0]);

  liftKj(args, [&]() -> void {
    request.context = nullptr;
    request.params = nullptr;
    KJ_IF_MAYBE(results, request.results) {
      results->get()->builder = nullptr;
    }
    request.fulfiller->reject(fromJsException(args[1]));
  });
}

// -----------------------------------------------------------------------------

#ifdef SANDSTORM_BUILD

class AlignedWords {
public:
  AlignedWords(kj::ArrayPtr<const kj::byte> bytes) {
    if (reinterpret_cast<uintptr_t>(bytes.begin()) % sizeof(capnp::word) != 0) {
      // Array is not aligned.  We have to make a copy.  :(
      copy = kj::heapArray<capnp::word>(bytes.size() / sizeof(capnp::word));
      memcpy(copy.begin(), bytes.begin(), copy.asBytes().size());
      words = copy;
    } else {
      // Yay, array is aligned.
      words = kj::arrayPtr(reinterpret_cast<const capnp::word*>(bytes.begin()),
                           bytes.size() / sizeof(capnp::word));
    }
  }

  inline const kj::ArrayPtr<const capnp::word>* operator->() const { return &words; }
  inline const kj::ArrayPtr<const capnp::word>& operator*() const { return words; }

private:
  kj::ArrayPtr<const capnp::word> words;
  kj::Array<capnp::word> copy;
};

bool matchPowerboxQuery(capnp::AnyPointer::Reader query, capnp::AnyPointer::Reader candidate);

bool matchPowerboxQuery(capnp::AnyStruct::Reader query, capnp::AnyStruct::Reader candidate) {
  {
    // Compare data.
    auto queryData = query.getDataSection();
    auto candidateData = candidate.getDataSection();

    auto commonSize = kj::min(queryData.size(), candidateData.size());
    if (memcmp(queryData.begin(), candidateData.begin(), commonSize) != 0) {
      // Data sections don't match.
      return false;
    }

    // Non-matched parts of data sections must be all-zero.
    kj::byte accum = 0;
    for (kj::byte b: queryData.slice(commonSize, queryData.size())) {
      accum |= b;
    }
    for (kj::byte b: candidateData.slice(commonSize, candidateData.size())) {
      accum |= b;
    }
    if (accum != 0) return false;
  }

  {
    // Compare pointers.
    auto queryPointers = query.getPointerSection();
    auto candidatePointers = candidate.getPointerSection();

    auto commonSize = kj::min(queryPointers.size(), candidatePointers.size());
    for (auto i: kj::range<decltype(commonSize)>(0, commonSize)) {
      if (!matchPowerboxQuery(queryPointers[i], candidatePointers[i])) {
        return false;
      }
    }

    // No need to compare the non-overlapping range since null pointers match anything.
  }

  return true;
}

bool matchPowerboxQuery(capnp::AnyList::Reader query, capnp::AnyList::Reader candidate) {
  auto elementSize = query.getElementSize();
  if (candidate.getElementSize() != elementSize) return false;

  switch (elementSize) {
    case capnp::ElementSize::VOID:
    case capnp::ElementSize::BIT:
    case capnp::ElementSize::BYTE:
    case capnp::ElementSize::TWO_BYTES:
    case capnp::ElementSize::FOUR_BYTES:
    case capnp::ElementSize::EIGHT_BYTES:
      return query == candidate;

    case capnp::ElementSize::POINTER: {
      auto queryPtrs = query.as<capnp::List<capnp::AnyPointer>>();
      auto candidatePtrs = candidate.as<capnp::List<capnp::AnyPointer>>();

      if (queryPtrs.size() != candidatePtrs.size()) return false;
      for (auto i: kj::indices(queryPtrs)) {
        if (!matchPowerboxQuery(queryPtrs[i], candidatePtrs[i])) return false;
      }
      return true;
    }

    case capnp::ElementSize::INLINE_COMPOSITE: {
      // Every element in the query must be matched by at least one element in the candidate.
      //
      // TODO(perf): O(m*n), can we do better?

      auto candidateStructs = candidate.as<capnp::List<capnp::AnyStruct>>();
      for (auto queryElement: query.as<capnp::List<capnp::AnyStruct>>()) {
        bool matched = false;
        for (auto candidateElement: candidateStructs) {
          if (matchPowerboxQuery(queryElement, candidateElement)) {
            matched = true;
            break;
          }
        }
        if (!matched) return false;
      }
      return true;
    }
  }
}

bool matchPowerboxQuery(capnp::AnyPointer::Reader query, capnp::AnyPointer::Reader candidate) {
  auto queryType = query.getPointerType();
  auto candidateType = candidate.getPointerType();

  if (queryType != candidateType) {
    // Different types -> no match, unless one is null, which is a wildcard.
    return queryType == capnp::PointerType::NULL_ ||
           candidateType == capnp::PointerType::NULL_;
  }

  switch (queryType) {
    case capnp::PointerType::NULL_:
      return true;
    case capnp::PointerType::STRUCT:
      return matchPowerboxQuery(query.getAs<capnp::AnyStruct>(),
                                candidate.getAs<capnp::AnyStruct>());
    case capnp::PointerType::LIST:
      return matchPowerboxQuery(query.getAs<capnp::AnyList>(),
                                candidate.getAs<capnp::AnyList>());
    case capnp::PointerType::CAPABILITY:
      // TODO(someday): Support matching capabilities?
      return false;
  }
}

void matchPowerboxQuery(const v8::FunctionCallbackInfo<v8::Value>& args) {
  // matchPowerboxQuery(queryBuffer, candidateBuffer) -> bool
  //
  // Decodes queryBuffer and candidateBuffer as capnp messages and returns true if the query
  // "matches" the candidate according to Sandstorm's powerbox query tag matching algorithm. See
  // PowerboxDescriptor::Tag::value in sandstorm/powerbox.capnp for full details of the algorithm.
  // The idea here is that the two parameters are AnyPointer values from Tag::value, which in
  // node-capnp are normally represented as byte arrays. Note that the order of the parameters
  // is important, particularly in the case of struct list matching.

  KJV8_UNWRAP(CapnpContext, context, args.Data());
  KJV8_UNWRAP_BUFFER(queryBuffer, args[0]);
  KJV8_UNWRAP_BUFFER(candidateBuffer, args[1]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    AlignedWords queryWords(queryBuffer);
    AlignedWords candidateWords(candidateBuffer);

    capnp::FlatArrayMessageReader queryReader(*queryWords);
    capnp::FlatArrayMessageReader candidateReader(*candidateWords);

    auto queryRoot = queryReader.getRoot<capnp::AnyPointer>();
    auto candidateRoot = candidateReader.getRoot<capnp::AnyPointer>();

    bool result = matchPowerboxQuery(queryRoot, candidateRoot);

    return v8::Boolean::New(args.GetIsolate(), result);
  });
}

void chacha20(const v8::FunctionCallbackInfo<v8::Value>& args) {
  KJV8_UNWRAP_BUFFER(message, args[0]);
  KJV8_UNWRAP_BUFFER(nonce, args[1]);
  KJV8_UNWRAP_BUFFER(key, args[2]);

  liftKj(args, [&]() -> v8::Local<v8::Value> {
    KJ_REQUIRE(key.size() == crypto_stream_chacha20_KEYBYTES);
    KJ_REQUIRE(nonce.size() == crypto_stream_chacha20_NONCEBYTES);

    auto maybeOut = node::Buffer::New(v8::Isolate::GetCurrent(), message.size());
    v8::Local<v8::Object> out;

    if (!maybeOut.ToLocal(&out)) {
      return emptyHandle;
    }

    auto outData = reinterpret_cast<byte*>(node::Buffer::Data(out));
    KJ_ASSERT(crypto_stream_chacha20_xor(
        outData, message.begin(), message.size(), nonce.begin(), key.begin()) == 0);

    return out;
  });
}

namespace {

void crashHandler(int signo, siginfo_t* info, void* context) {
  void* traceSpace[32];

  // ignoreCount = 2 to ignore crashHandler() and signal trampoline.
  auto trace = kj::getStackTrace(traceSpace, 2);

  auto message = kj::str("*** Received signal #", signo, ": ", strsignal(signo),
                         "\nstack: ", stringifyStackTraceAddresses(trace), '\n');

  kj::FdOutputStream(STDERR_FILENO).write(message.begin(), message.size());
  _exit(1);
}

}  // namespace

void catchSegfaults() {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESETHAND;
  action.sa_sigaction = &crashHandler;
  KJ_SYSCALL(sigaction(SIGSEGV, &action, nullptr));
}

#endif // SANDSTORM_BUILD

// -----------------------------------------------------------------------------

void init(v8::Local<v8::Object> exports) {
  CapnpContext* context = new CapnpContext;
  auto wrappedContext = context->wrapper.wrap(context);

  auto mapFunction = [&](const char* name, v8::FunctionCallback callback) {
    exports->Set(v8::Isolate::GetCurrent()->GetCurrentContext(), newSymbol(name),
        v8::FunctionTemplate::New(v8::Isolate::GetCurrent(), callback, wrappedContext)
            ->GetFunction(v8::Isolate::GetCurrent()->GetCurrentContext()).ToLocalChecked()).Check();
  };

  mapFunction("setNative", setNative);
  mapFunction("import", import);
  mapFunction("methods", methods);
  mapFunction("newBuilder", newBuilder);
  mapFunction("copyBuilder", copyBuilder);
  mapFunction("structToString", structToString);
  mapFunction("fromJs", fromJs);
  mapFunction("toJs", toJs);
  mapFunction("toJsParams", toJsParams);
  mapFunction("expectedSizeFromPrefix", expectedSizeFromPrefix);
  mapFunction("fromBytes", fromBytes);
  mapFunction("toBytes", toBytes);
  mapFunction("connect", connect);
  mapFunction("connectUnixFd", connectUnixFd);
  mapFunction("disconnect", disconnect);
  mapFunction("restore", restore);
  mapFunction("castAs", castAs);
  mapFunction("schemaFor", schemaFor);
  mapFunction("close", closeCap);
  mapFunction("release", release);
  mapFunction("dup", dupCap);
  mapFunction("dup2", dup2Cap);
  mapFunction("request", request);
  mapFunction("send", send);
  mapFunction("cancel", cancel);
  mapFunction("newCap", newCap);
  mapFunction("newPromisedCap", newPromisedCap);
  mapFunction("fulfillPromisedCap", fulfillPromisedCap);
  mapFunction("rejectPromisedCap", rejectPromisedCap);
  mapFunction("isCap", isCap);
  mapFunction("releaseParams", releaseParams);
  mapFunction("getResults", getResults);
  mapFunction("return_", return_);
  mapFunction("throw_", throw_);

#ifdef SANDSTORM_BUILD
  mapFunction("matchPowerboxQuery", matchPowerboxQuery);
  mapFunction("chacha20", chacha20);
  catchSegfaults();
#endif
}

}  // namespace
}  // namespace v8capnp

NODE_MODULE(capnp, v8capnp::init)
