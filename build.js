#!/usr/bin/env node

// build.js copied from node-fibers package under MIT license.
// License for node-fibers is as follows:
//
// Copyright 2011 Marcel Laverdet
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

var cp = require('child_process'),
	fs = require('fs'),
	path = require('path');

// Parse args
var force = false, debug = false;
var
	arch = process.arch,
	platform = process.platform,
	v8 = /[0-9]+\.[0-9]+/.exec(process.versions.v8)[0];
var args = process.argv.slice(2).filter(function(arg) {
	if (arg === '-f') {
		force = true;
		return false;
	} else if (arg.substring(0, 13) === '--target_arch') {
		arch = arg.substring(14);
	} else if (arg === '--debug') {
		debug = true;
	}
	return true;
});
if (!{ia32: true, x64: true, arm: true}.hasOwnProperty(arch)) {
	console.error('Unsupported (?) architecture: `'+ arch+ '`');
	process.exit(1);
}

// Test for pre-built library
var modPath = platform+ '-'+ arch+ '-v8-'+ v8;
if (!force) {
	try {
		fs.statSync(path.join(__dirname, 'bin', modPath, 'capnp.node'));
		console.log('`'+ modPath+ '` exists; testing');
		cp.execFile(process.execPath, ['src/node-capnp/capnp-test'], function(err, stdout, stderr) {
			if (err || stdout.trim() !== 'pass' || stderr) {
				console.log('Problem with the binary; manual build incoming');
				build();
			} else {
				console.log('Binary is fine; exiting');
			}
		});
	} catch (ex) {
		// Stat failed
		build();
	}
} else {
	build();
}

// Build it
function build() {
	var sp = cp.spawn(
		process.platform === 'win32' ? 'node-gyp.cmd' : 'node-gyp',
		['rebuild'].concat(args),
		{customFds: [0, 1, 2]});

	sp
	.on('close', function(){ afterBuild(); })
	.on('exit', function(err) {
		if (err) {
			if (err === 127) {
				console.error(
					'node-gyp not found! Please upgrade your install of npm! You need at least 1.1.5 (I think) '+
					'and preferably 1.1.30.'
				);
			} else {
				console.error('Build failed');
			}
			return process.exit(err);
		}
	});
	sp.stdout.pipe(process.stdout);
	sp.stderr.pipe(process.stderr);
}

// Move it to expected location
function afterBuild() {
	var targetPath = path.join(__dirname, 'build', debug ? 'Debug' : 'Release', 'capnp.node');
	var installPath = path.join(__dirname, 'bin', modPath, 'capnp.node');

	try {
		fs.mkdirSync(path.join(__dirname, 'bin', modPath));
	} catch (ex) {}

	try {
		fs.statSync(targetPath);
	} catch (ex) {
		console.error('Build succeeded but target not found');
		process.exit(1);
	}
	fs.renameSync(targetPath, installPath);
	console.log('Installed in `'+ installPath+ '`');
}

