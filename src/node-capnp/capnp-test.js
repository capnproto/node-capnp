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

var fs = require("fs");
var capnp = require("./capnp");
var assert = require("assert");
var spawn = require("child_process").spawn;

var goldenBinary;
var goldenPackedBinary;
var goldenFlatBinary;
var goldenPackedFlatBinary;
try {
  // Works in Ekam build.
  goldenBinary = fs.readFileSync("node-capnp/testdata/binary");
  goldenPackedBinary = fs.readFileSync("node-capnp/testdata/packedbinary");
  goldenFlatBinary = fs.readFileSync("node-capnp/testdata/flat");
  goldenPackedFlatBinary = fs.readFileSync("node-capnp/testdata/packedflat");
} catch (ex) {
  // Works in npm build.
  goldenBinary = fs.readFileSync("src/node-capnp/testdata/binary");
  goldenPackedBinary = fs.readFileSync("src/node-capnp/testdata/packedbinary");
  goldenFlatBinary = fs.readFileSync("src/node-capnp/testdata/flat");
  goldenPackedFlatBinary = fs.readFileSync("src/node-capnp/testdata/packedflat");
}

var test = require("./test.capnp");
assert(test === capnp.import(__dirname + "/test.capnp"));
assert(test === require("./test"));

assert("namespace" in capnp.importSystem("capnp/c++.capnp"));

var parsed = capnp.parse(test.TestAllTypes, goldenBinary);

var roundTripped = capnp.serialize(test.TestAllTypes, parsed);

var canon = capnp.bytesToPreorder(test.TestAllTypes, roundTripped);

assert.equal(goldenBinary.length, roundTripped.length, "Round trip changed size?");
assert.equal(goldenBinary.toString("base64"), canon.toString("base64"), "Round trip lost data?");

assert.equal(3456789012, test.TestConstants.uint32Const);
assert.equal("foo", test.TestConstants.textConst);
assert.equal("baz", test.TestConstants.structConst.textField);
assert.equal("xyzzy", test.TestConstants.textListConst[1]);

// Test packed serialization/deserialization

var parsedPacked = capnp.parsePacked(test.TestAllTypes, goldenPackedBinary);
var roundTrippedPacked = capnp.serializePacked(test.TestAllTypes, parsedPacked);
assert.equal(goldenPackedBinary.length, roundTrippedPacked.length, "Round trip changed size?");
assert.equal(goldenPackedBinary.toString("base64"), roundTrippedPacked.toString("base64"), "Round trip lost data?");

var parsedFlat = capnp.parse(test.TestAllTypes, goldenFlatBinary, {flat: true});
var roundTrippedFlat = capnp.serialize(test.TestAllTypes, parsedFlat, {flat: true});
assert.equal(goldenFlatBinary.length, roundTrippedFlat.length, "Round trip changed size?");
assert.equal(goldenFlatBinary.toString("base64"), roundTrippedFlat.toString("base64"), "Round trip lost data?");

var parsedPackedFlat = capnp.parse(test.TestAllTypes, goldenPackedFlatBinary, {packed: true, flat: true});
var roundTrippedPackedFlat = capnp.serialize(test.TestAllTypes, parsedPackedFlat, {packed: true, flat: true});
assert.equal(goldenPackedFlatBinary.length, roundTrippedPackedFlat.length, "Round trip changed size?");
assert.equal(goldenPackedFlatBinary.toString("base64"), roundTrippedPackedFlat.toString("base64"), "Round trip lost data?");

// TODO(someday): do a more thorough deep equality comparison of parsed and parsedPacked
var keys = ["voidField", "boolField", "int8Field", "int16Field", "int32Field", "int64Field"];
for (var key in keys) {
  assert.equal(parsed[key], parsedPacked[key]);
  assert.equal(parsed[key], parsedFlat[key]);
  assert.equal(parsed[key], parsedPackedFlat[key]);
}

// =======================================================================================

/*
// TODO(someday): Revive this test. The main problem is that it depends on calculator-server from
//   the Cap'n Proto samples directory.

var Fiber = require("fibers");

function wait(promise) {
  var fiber = Fiber.current;
  var success, result, error;
  promise.then(function (p) {
    success = true;
    result = p;
    fiber.run();
  }, function (e) {
    success = false;
    error = e;
    fiber.run();
  });
  Fiber.yield();
  if (success) {
    return result;
  } else {
    throw error;
  }
}

function doFiber(func, child) {
  new Fiber(function () {
    try {
      func();
      if (child) {
        child.kill();
        child.unref();
      }
    } catch (err) {
      console.log(err.stack);
      if (child) {
        child.kill();
        child.unref();
      }
      process.exit(1);
    }
  }).run();
}

var child = spawn("capnp-samples/calculator-server", ["127.0.0.1:21311"],
                  {stdio: [0, "pipe", 2], env: {}});

child.stdio[1].once("readable", function() {
  child.stdio[1].resume();  // ignore all input

  doFiber(function() {
    var conn = capnp.connect("127.0.0.1:21311");
    var Calculator = capnp.import("capnp-samples/calculator.capnp").Calculator;
    var calc = conn.restore("calculator", Calculator);

    var add = calc.getOperator("add").func;
    var subtract = calc.getOperator("subtract").func;
    var pow = {
      call: function (params) {
        return Math.pow(params[0], params[1]);
      },
      close: function () {
        this.closed = true;
      },
      closed: false
    };

    var localCap = new capnp.Capability(pow, Calculator.Function);
    assert.equal(9, wait(localCap.call([3, 2])).value);
    assert(!pow.closed);
    localCap.close();
    assert(pow.closed);

    var promise = calc.evaluate(
        {call: {"function": subtract, params: [
            {call: {"function": add, params: [
                {literal: 123}, {literal: 456}]}},
            {literal: 321}]}});

    var value = promise.value;
    assert.equal(258, wait(value.read()).value);
    value.close();

    pow.closed = false;
    value = calc.evaluate(
        {call: {"function": pow, params: [{literal: 2}, {literal: 4}]}}).value;
    assert.equal(16, wait(value.read()).value);
    assert(pow.closed);  // Not kept past return.
    value.close();

    // Try wrapping a promise as a capability -- calls are queued until resolution.
    var resolvePromisedCalc;
    var promisedCalc = new capnp.Capability(new Promise(function (resolve, reject) {
      resolvePromisedCalc = resolve;
    }), Calculator);

    value = promisedCalc.evaluate(
        {call: {"function": add, params: [
            {literal: 123}, {literal: 321}]}}).value;
    promise = value.read();
    resolvePromisedCalc(calc);
    assert.equal(444, wait(promise).value);
    value.close();

    // Like above, but reject the promise so queued calls fail.
    var rejectPromisedCalc;
    promisedCalc = new capnp.Capability(new Promise(function (resolve, reject) {
      rejectPromisedCalc = reject;
    }), Calculator);

    value = promisedCalc.evaluate(
        {call: {"function": add, params: [
            {literal: 123}, {literal: 321}]}}).value;
    promise = value.read();
    rejectPromisedCalc(new Error("foo example error"));
    assert.throws(function() { wait(promise); }, /foo example error/);
    value.close();

    add.close();
    subtract.close();
    conn.close();

    console.log("rpc: pass");
  }, child);
});
*/

console.log("pass");

