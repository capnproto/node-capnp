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
  fs.statSync(modPath+ ".node");
} catch (ex) {
  // No binary!
  throw new Error(
      "`" + modPath+ ".node` is missing. Try reinstalling `node-capnp`?");
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
        // Otherwise, overwrite the pipelined cap with the final cap.
        if (pmember.closed) {
          fmember.close();
        } else {
          v8capnp.dup2(fmember, pmember);
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
      pipeline = v8capnp.send(req, resolve, reject, Capability);
    }).then(function (response) {
      var result = v8capnp.toJs(response, Capability);
      settleCaps(pipeline, result);
      return result;
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
    var method = obj[name];
    if (typeof method === "function") {
      this[name] = wrapLocalMethod(obj, method);
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

  var methods = v8capnp.methods(schema);

  for (var name in methods) {
    this[name] = makeMethod(native, methods[name]);
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

exports.connect = function (addr) {
  return new Connection(v8capnp.connect(addr));
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

