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

var path = require("path");
var fs = require("fs");

// Look for binary for this platform
var v8 = "v8-"+ /[0-9]+\.[0-9]+/.exec(process.versions.v8)[0];
var modPath = path.join(
    __dirname, "../../bin", process.platform+ "-" + process.arch + "-" + v8,
    "capnp");
try {
  fs.statSync(modPath + ".node");
} catch (ex) {
  // No binary!

  // Also try just "capnp.node". (Mainly for use when building with Ekam rather
  // than npm.)
  modPath = "./capnp.node";
  try {
    fs.statSync(path.join(__dirname, "capnp.node"));
  } catch (ex) {
    // Give up.
    throw new Error(
        "`" + modPath+ ".node` is missing. Try reinstalling `node-capnp`?");
  }
}

var v8capnp = require(modPath);
var Promise = require("es6-promise").Promise;

var importPath = [];
for (var i in module.paths) {
  importPath.push(module.paths[i]);
}

if ("NODE_PATH" in process.env) {
  var parts = process.env.NODE_PATH.split(path.delimiter);
  for (var j in parts) {
    importPath.push(parts[j]);
  }
}

// Also include standard places where .capnp files are installed.
importPath.push("/usr/local/include");
importPath.push("/usr/include");

exports.import = function (filename) {
  return v8capnp.import(filename, filename, importPath);
}

exports.importSystem = function (filename) {
  for (var i in importPath) {
    var candidate = path.join(importPath[i], filename);
    if (fs.existsSync(candidate)) {
      return v8capnp.import(filename, candidate, importPath);
    }
  }
  throw new Error("Cap'n Proto schema not found in module path: " + filename);
}

require.extensions[".capnp"] = function (module, filename) {
  module.exports = v8capnp.import(filename, filename, importPath);
}

function makeRemotePromise(promise, pipeline) {
  for (member in pipeline) {
    promise[member] = pipeline[member];
  }

  promise.cancel = function () {
    v8capnp.cancel(pipeline);
    closeAll(pipeline);
    promise.then(function (response) {
      closeAll(response);
    });
  }
}

function closeAll(obj) {
  for (var name in obj) {
    var member = obj[name];
    if (member instanceof Capability) {
      member.close();
    } else {
      closeAll(member);
    }
  }
}

function settleCaps(pipeline, final) {
  for (var name in pipeline) {
    var pmember = pipeline[name];

    if (name in final) {
      var fmember = final[name];

      if (pmember instanceof Capability) {
        // If pipelined capability was closed, close the final cap.
        // Otherwise, merge the two caps so closing either one closes both.
        if (pmember.closed) {
          fmember.close();
        } else {
          // This is tricky. We have two capabilities that ultimately point to the same place, but
          // we don't want the user to have to close both independently. We want to end up with one
          // capability object. However, pmember has already been out and about, so application
          // code might already be holding a reference to it. We can use dup2() to redirect the
          // reference to the new capability instead, but we still end up with two capabilities
          // that each need closing.
          //
          // Luckily, fmember has NOT been passed to application code yet. So we can actually close
          // it, and then replace the slot in the parent object. Application code will never know
          // the difference. Hah!
          v8capnp.dup2(fmember, pmember);
          fmember.close();
          final[name] = pmember;
        }
      } else {
        // Recurse into struct.
        settleCaps(pmember, fmember);
      }
    } else {
      if (pmember instanceof Capability) {
        pmember.close();
      } else {
        settleCaps(pmember, {});
      }
    }
  }
}

function makeMethod(cap, method) {
  return function () {
    var req = v8capnp.request(cap, method);
    v8capnp.fromJs(req, Array.prototype.slice.call(arguments, 0), LocalCapWrapper);
    var pipeline;
    var promise = new Promise(function (resolve, reject) {
      pipeline = v8capnp.send(req, function (x) {
        if (verboseDebugLogging) console.log("capnp.js: returned to JS 1", v8capnp.methodName(method));
        resolve(x);
      }, function (x) {
        if (verboseDebugLogging) console.log("capnp.js: threw to JS 1", v8capnp.methodName(method), x);
        reject(x);
      }, Capability);
    }).then(function (response) {
      if (verboseDebugLogging) console.log("capnp.js: returned to JS 2", v8capnp.methodName(method));
      var result = v8capnp.toJs(response, Capability);
      v8capnp.release(response);
      settleCaps(pipeline, result);
      if (verboseDebugLogging) console.log("capnp.js: returned to JS 3", v8capnp.methodName(method));
      return result;
    }, function (err) {
      if (verboseDebugLogging) console.log("capnp.js: threw to JS 2", v8capnp.methodName(method));
      throw err;
    });
    makeRemotePromise(promise, pipeline);
    return promise;
  }
}

function wrapLocalMethod(self, method) {
  return function (request) {
    var params = v8capnp.toJsParams(request, Capability);
    v8capnp.releaseParams(request);
    Promise.resolve(method.apply(self, params)).then(function (results) {
      if (typeof results !== "object") {
        if (results === undefined) {
          results = [];
        } else {
          // Wrap single primitive return value in an array.
          results = [results];
        }
      }
      v8capnp.fromJs(v8capnp.getResults(request), results, LocalCapWrapper);
      v8capnp.return_(request);
    }).catch(function (error) {
      v8capnp.throw_(request, error);
    }).catch(function (error) {
      console.error("Cap'n Proto v8 bug when returning from incoming method call:", error);
    });
  }
}

function LocalCapWrapper(obj) {
  for (var name in obj) {
    if (name === "close") {
      // Not an RPC method. Called when the capability has no clients.
      this.close = obj.close.bind(obj);
    } else {
      var method = obj[name];
      if (typeof method === "function") {
        this[name] = wrapLocalMethod(obj, method);
      }
    }
  }
}

function Capability(native, schema) {
  // If `native` is actually a local object, wrap it as a capability.
  if (!v8capnp.isCap(native)) {
    if (native instanceof Promise) {
      // Oh, it's a promise. Wrap it in a capability.
      var promisedCap = v8capnp.newPromisedCap(schema);
      var fulfiller = promisedCap.fulfiller;
      native.then(v8capnp.fulfillPromisedCap.bind(this, fulfiller))
            .catch(v8capnp.rejectPromisedCap.bind(this, fulfiller));
      native = promisedCap.cap;
    } else {
      // Local object.
      native = v8capnp.newCap(schema, new LocalCapWrapper(native));
    }
  }

  v8capnp.setNative(this, native);

  if (schema) {
    var methods = v8capnp.methods(schema);

    for (var name in methods) {
      this[name] = makeMethod(native, methods[name]);
    }
  }

  this.close = function () { v8capnp.close(native); this.closed = true; }
  this.closed = false;
  this.clone = function () { return new Capability(v8capnp.dup(native), schema); }
  this.castAs = function (newSchema) {
    return new Capability(v8capnp.castAs(native, newSchema), newSchema);
  }
  this.schema = schema;

  Object.freeze(this);
}

function Connection(native) {
  this.restore = function (objectId, schema) {
    return new Capability(v8capnp.restore(native, objectId, schema), schema);
  }

  this.close = function () {
    v8capnp.disconnect(native);
  }
}

exports.connect = function (addr, bootstrapCap) {
  if (bootstrapCap && !v8capnp.isCap(bootstrapCap)) {
    throw new Error("Invalid bootstrap capability.");
  }
  return new Connection(v8capnp.connect(addr, bootstrapCap));
}

exports.parse = function (schema, buffer) {
  var reader = v8capnp.fromBytes(buffer, schema);
  return v8capnp.toJs(reader, Capability);
}

exports.serialize = function (schema, value) {
  var builder = v8capnp.newBuilder(schema);
  v8capnp.fromJs(builder, value, LocalCapWrapper);
  return v8capnp.toBytes(builder);
}

exports.Capability = Capability;

exports.bytesToPreorder = function(schema, buf) {
  // Parse, copy, serialize, to get a preorder traversal.
  var reader = v8capnp.fromBytes(buf, schema);
  var builder = v8capnp.copyBuilder(reader);
  return v8capnp.toBytes(builder);
}

var verboseDebugLogging = false;
exports.enableVerboseDebugLogging = function (flag) {
  verboseDebugLogging = flag;
  v8capnp.enableVerboseDebugLogging(flag);
}
