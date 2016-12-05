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

console.log("serialization: pass");

// =======================================================================================
// Test matchPowerboxQuery

var tag1 = capnp.serialize(test.TestAllTypes, {int32Field: 123});
var tag2 = capnp.serialize(test.TestAllTypes, {int32Field: 321});
var tag3 = capnp.serialize(test.TestAllTypes, {});

assert(capnp.matchPowerboxQuery(tag1, tag1));
assert(capnp.matchPowerboxQuery(tag2, tag2));
assert(capnp.matchPowerboxQuery(tag3, tag3));

assert(!capnp.matchPowerboxQuery(tag1, tag2));
assert(!capnp.matchPowerboxQuery(tag2, tag3));
assert(!capnp.matchPowerboxQuery(tag3, tag1));

var emptyTag = capnp.serialize(test.TestEmptyStruct, {});
assert(!capnp.matchPowerboxQuery(emptyTag, tag1));
assert(!capnp.matchPowerboxQuery(emptyTag, tag2));
assert(capnp.matchPowerboxQuery(emptyTag, tag3));
assert(!capnp.matchPowerboxQuery(tag1, emptyTag));
assert(!capnp.matchPowerboxQuery(tag2, emptyTag));
assert(capnp.matchPowerboxQuery(tag3, emptyTag));

var tagStr1 = capnp.serialize(test.TestAllTypes, {textField: "foo"});
var tagStr2 = capnp.serialize(test.TestAllTypes, {textField: "bar"});
var tagStr3 = capnp.serialize(test.TestAllTypes, {textField: ""});
assert(capnp.matchPowerboxQuery(tagStr1, tagStr1));
assert(capnp.matchPowerboxQuery(tagStr2, tagStr2));
assert(capnp.matchPowerboxQuery(tagStr3, tagStr3));
assert(!capnp.matchPowerboxQuery(tagStr1, tagStr2));
assert(!capnp.matchPowerboxQuery(tagStr2, tagStr3));
assert(!capnp.matchPowerboxQuery(tagStr3, tagStr1));
assert(capnp.matchPowerboxQuery(tagStr1, emptyTag));
assert(capnp.matchPowerboxQuery(tagStr2, emptyTag));
assert(capnp.matchPowerboxQuery(tagStr3, emptyTag));
assert(capnp.matchPowerboxQuery(emptyTag, tagStr1));
assert(capnp.matchPowerboxQuery(emptyTag, tagStr2));
assert(capnp.matchPowerboxQuery(emptyTag, tagStr3));

var tagStr3 = capnp.serialize(test.TestAllTypes, {textField: "oof"});
assert(!capnp.matchPowerboxQuery(tagStr1, tagStr3));

var tagFooBar = capnp.serialize(test.TestAllTypes,
    {structList: [{textField: "foo"}, {textField: "bar"}]});
var tagFooOnly = capnp.serialize(test.TestAllTypes,
    {structList: [{textField: "foo"}]});
var tagBarOnly = capnp.serialize(test.TestAllTypes,
    {structList: [{textField: "bar"}]});
var tagEmptyList = capnp.serialize(test.TestAllTypes,
    {structList: []});

assert(capnp.matchPowerboxQuery(tagFooBar, tagFooBar));
assert(capnp.matchPowerboxQuery(tagFooOnly, tagFooBar));
assert(capnp.matchPowerboxQuery(tagBarOnly, tagFooBar));
assert(!capnp.matchPowerboxQuery(tagFooBar, tagFooOnly));
assert(!capnp.matchPowerboxQuery(tagFooBar, tagBarOnly));

assert(capnp.matchPowerboxQuery(tagFooBar, emptyTag));
assert(capnp.matchPowerboxQuery(tagFooOnly, emptyTag));
assert(capnp.matchPowerboxQuery(tagBarOnly, emptyTag));
assert(capnp.matchPowerboxQuery(emptyTag, tagFooBar));
assert(capnp.matchPowerboxQuery(emptyTag, tagFooOnly));
assert(capnp.matchPowerboxQuery(emptyTag, tagBarOnly));

assert(!capnp.matchPowerboxQuery(tagFooBar, tagEmptyList));
assert(!capnp.matchPowerboxQuery(tagFooOnly, tagEmptyList));
assert(!capnp.matchPowerboxQuery(tagBarOnly, tagEmptyList));
assert(capnp.matchPowerboxQuery(tagEmptyList, tagFooBar));
assert(capnp.matchPowerboxQuery(tagEmptyList, tagFooOnly));
assert(capnp.matchPowerboxQuery(tagEmptyList, tagBarOnly));

console.log("matchPowerboxQuery: pass");

// =======================================================================================
// Test RPC, if possible.

if (!fs.existsSync("capnp-samples")) {
  console.warn("skipping RPC because capnp-samples not present");
  process.exit(0);
}

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
    var calc = conn.restore(null, Calculator);

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

    // Wait a moment to give the capability a chance to be dropped.
    wait(new Promise((resolve, reject) => setTimeout(resolve, 10)));
    assert(pow.closed);
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
    calc.close();
    conn.close();

    console.log("rpc: pass");
  }, child);
});
