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

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const yargs = require("yargs");

/*
Parse command-line arguments using `yargs`. Parsed values are stored in the `args` global.
*/

const args = yargs
  .option("target-platform", {
    description: "The target platform for cross-compilation.",
    type: "string",
    choices: ["win32", "darwin", "linux"],

    // The default platform is the `npm_config_platform` environment variable if it's set, or
    // `process.platform` otherwise. That environment variable will be set when a `--platform`
    // argument is passed to `npm install` while installing this package as a dependency; this is
    // the same cross-compilation CLI provided by Electron.
    default: process.env.npm_config_platform || process.platform,
  })
  .option("target-arch", {
    description: "The target architecture for cross-compilation.",
    type: "string",
    choices: ["ia32", "x64", "arm64"],
    default: process.env.npm_config_arch || process.arch,
  })
  .option("debug", {
    description: "Request a debug build from node-gyp.",
    type: "boolean",
    default: false,
  })
  .option("dist-url", {
    description: "Passed unchanged to node-gyp.",
    type: "string",
  })
  .option("target", {
    description: "Passed unchanged to node-gyp.",
    type: "string",
  })
  .strict()
  .help().argv;

/*
We only support certain combinations of host and target.

(TODO: Could a Darwin host also run `build-capnp.sh`? Do we care about that?)
*/

const hostAndTargetSupported =
  (process.platform === "linux" && args.targetPlatform === "linux") ||
  (process.platform === "linux" && args.targetPlatform === "darwin") ||
  (process.platform === "linux" && args.targetPlatform === "win32") ||
  (process.platform === "win32" && args.targetPlatform === "win32");

if (!hostAndTargetSupported) {
  console.error(
    `We can't build this package for a ${args.targetPlatform} target ` +
      `from a ${process.platform} host.`
  );
  process.exit(1);
}

/*
Build the capnp libraries and include files into a `./build-capnp` subdirectory.

For simplicity, when building `capnp.node`, we always start by rebuilding the capnp library from
scratch.
*/

function buildCapnp() {
  let buildCapnpResult;

  if (process.platform === "linux") {
    /*
    Build the capnp library on Linux, perhaps cross-compiling to Darwin.
    */

    if (args.targetPlatform !== "linux" && args.targetPlatform !== "darwin") {
      throw new Error(
        `Unexpected target ${args.targetPlatform} when building on a Linux host.`
      );
    }

    buildCapnpResult = childProcess.spawnSync(
      "./build-capnp.sh",
      [args.targetPlatform, args.targetArch],
      {
        stdio: "inherit",
      }
    );
  } else if (process.platform === "win32") {
    /*
    Build the capnp library on Win32, for a Win32 target.
    */

    if (args.targetPlatform !== "win32") {
      throw new Error(
        `Unexpected target ${args.targetPlatform} when building on a Win32 host.`
      );
    }

    buildCapnpResult = childProcess.spawnSync("build-capnp.bat", [], {
      stdio: "inherit",
      // shell: true is required on Windows since node v20.12.2:
      // https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2
      shell: true
    });
  } else {
    throw new Error(
      `Unexpected host platform ${process.platform}; expected linux or win32.`
    );
  }

  if (buildCapnpResult.error) {
    throw buildCapnpResult.error;
  }

  if (buildCapnpResult.status !== 0) {
    process.exit(buildCapnpResult.status);
  }
}

// TODO: Ideally these paths shouldn't be hardcoded, but I can't see a clean workaround...
let capnpLibPath, capnpIncPath, patchLibPath;

if (process.platform === "linux") {
  capnpLibPath = path.resolve("./build-capnp/.libs");
  capnpIncPath = path.resolve("./build-capnp/capnp-root/usr/local/include");
  patchLibPath = ".libs";
} else if (process.platform === "win32") {
  capnpLibPath = path.resolve("./build-capnp/.libs");
  capnpIncPath = path.resolve("./build-capnp/src/");
  patchLibPath = undefined; // Unused, since we don't support win32->darwin builds
} else {
  throw new Error(
    `Building on platform ${JSON.stringify(
      process.platform
    )} is not yet supported.`
  );
}

/*
When we expect to run the `node-gyp` compiler, we configure it by passing in additional environment
variables.
*/

let buildEnvironment = Object.assign({}, process.env);

if (process.platform === "linux" && args.targetPlatform === "linux") {
  buildEnvironment.CC = "clang";
  buildEnvironment.CXX = "clang++";
  buildEnvironment.CFLAGS = "-I" + capnpIncPath;
  buildEnvironment.CXXFLAGS = buildEnvironment.CFLAGS + " -std=c++20";
  buildEnvironment.LDFLAGS = "-L" + capnpLibPath;
}

if (process.platform === "linux" && args.targetPlatform === "darwin") {
  // This env var is made available by osxcross.
  const darwinTarget = process.env.OSXCROSS_TARGET || "darwin24.5";

  if (args.targetArch === "x64") {
    buildEnvironment.CC = "o64-clang";
    buildEnvironment.CXX = "o64-clang++";
    buildEnvironment.PATCH_TOOL = `x86_64-apple-${darwinTarget}-install_name_tool`;
  } else if (args.targetArch == "arm64") {
    buildEnvironment.CC = "oa64-clang";
    buildEnvironment.CXX = "oa64-clang++";
    buildEnvironment.PATCH_TOOL = `arm64-apple-${darwinTarget}-install_name_tool`;
  } else {
      throw new Error(`Bad target architecture ${args.targetArch} for darwin cross-compilation`);
  }

  buildEnvironment.CFLAGS =
    "-mmacosx-version-min=13.0 -std=c++20 " +
    "-stdlib=libc++ -I" +
    capnpIncPath;
  buildEnvironment.CXXFLAGS = buildEnvironment.CFLAGS;
  buildEnvironment.LDFLAGS = "-L" + capnpLibPath;

}

if (process.platform === "win32" && args.targetPlatform === "win32") {
  buildEnvironment.CL = `/I ${capnpIncPath}`;
  buildEnvironment.LINK = `/LIBPATH:${capnpLibPath}`;
}

/**
 * Build `capnp.node` using `node-gyp`.
 *
 * @param buildEnvironment - the set of environment variables to pass to `node-gyp`
 */
function build(buildEnvironment) {
  buildCapnp();

  console.log(
    `Building with the following environment:\n${JSON.stringify(
      buildEnvironment,
      null,
      "\t"
    )}`
  );

  // Collate arguments for `node-gyp configure` and `node-gyp build`.
  let buildArgs = ["--verbose"];

  if (args.targetArch !== process.arch) {
    buildArgs.push(`--arch=${args.targetArch}`);
  }

  if (args.debug) {
    buildArgs.push("--debug");
  }

  if (args.distUrl) {
    buildArgs.push(`--dist-url=${args.distUrl}`);
  }

  if (args.target) {
    buildArgs.push(`--target=${args.target}`);
  }

  // The arguments for `node-gyp configure` may differ slightly from those for `node-gyp build`.
  let configureArgs = [...buildArgs];

  if (args.targetPlatform === "darwin") {
    // Pass all subsequent arguments through to `gyp` rather than `node-gyp`.
    configureArgs.push("--");

    // If we are cross-compiling for darwin, we must instruct gyp to generate a Makefile which is
    // compatible with the MacOS tooling. We must use the -f variant (not --format=) because it
    // overrides -f set by node-gyp, and node-gyp isn't clever enough to know that they're aliases.
    configureArgs.push("-f", "make-mac");
  }

  const runNodeGyp = (taskName, taskArgs) => {
    const command = process.platform === "win32" ? "node-gyp.cmd" : "node-gyp";
    const commandArgs = [taskName, ...taskArgs];

    console.log(
      `Executing ${command} with the following arguments:\n${commandArgs}`
    );

    const spawnSyncOptions = {
      stdio: "inherit",
      env: buildEnvironment,
    };

    if (process.platform === "win32") {
      // shell: true is required on Windows since node v20.12.2:
      // https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2
      spawnSyncOptions.shell = true;
    }

    const nodeGypResult = childProcess.spawnSync(command, commandArgs, spawnSyncOptions);

    if (nodeGypResult.error) {
      throw nodeGypResult.error;
    }

    if (nodeGypResult.status === 127) {
      console.error(
        "node-gyp not found! Please upgrade your install of npm! You need at least 1.1.5 " +
          "(I think) and preferably 1.1.30."
      );
      process.exit(1);
    }

    if (nodeGypResult.status !== 0) {
      console.error(
        `Build step ${taskName} failed with exit code ${nodeGypResult.status}.`
      );
      process.exit(1);
    }
  };

  runNodeGyp("clean", []);
  runNodeGyp("configure", configureArgs);
  runNodeGyp("build", buildArgs);
}

/**
 * Move the build result to the expected location.
 *
 * @param builtPath - a path to the compiled `capnp.node` file
 * @param buildEnvironment - a set of environment variables, perhaps including PATCH_TOOL
 */
function moveBuildResult(builtPath, buildEnvironment) {
  // We do not use the V8 version in the target dir, as the V8 version we are running with
  // currently may not be the same as that we are building for.
  const dirName = args.targetPlatform + "-" + args.targetArch;
  const installPath = path.join(__dirname, "bin", dirName, "capnp.node");

  try {
    fs.mkdirSync(path.join(__dirname, "bin", dirName), {
      recursive: true,
    });
  } catch (ex) {}

  try {
    fs.statSync(builtPath);
  } catch (ex) {
    console.error("Build succeeded but target not found");
    process.exit(1);
  }

  if (args.targetPlatform === "darwin") {
    patchLibs(buildEnvironment.PATCH_TOOL, patchLibPath, builtPath);
  }

  try {
    fs.copyFileSync(builtPath, installPath);
    console.log("Installed in `" + installPath + "`");
  } catch (ex) {
    console.error(`All went wrong when we tried to move the target: ${ex}`);
  }
}

/**
 * Rewrite the dynamic library references in the produced bundle to have appropriate paths for
 * relative layout within the final application bundle.
 *
 * @param patchTool - command name to use for editing the binary
 * @param patchPath - the path to be stripped out of the binary
 * @param target - The target binary to be modified
 */
function patchLibs(patchTool, patchPath, target) {
  var libVersion = "1.1.0";
  var libExt = "so";
  var libs = ["libkj", "libkj-async", "libcapnp", "libcapnpc", "libcapnp-rpc"];

  var patchArgs = libs
    .flatMap((lib) => {
      return [
        "-change",
        `${patchPath}/${lib}-${libVersion}.${libExt}`,
        `@executable_path/${lib}-${libVersion}.dylib`,
      ];
    })
    .concat([target]);

  console.log(
    `Invoking binary patch tool ${patchTool} with the following arguments:`
  );
  console.log(patchArgs);

  // In future if this errors, we may need to set headerpad_max_install_names in LDFLAGS too...
  // (this provides more space for the dylib names in the object so that they can be rewritten
  // post-link) - looks like we don't need to do this for now though?
  var patchProcess = childProcess.spawnSync(patchTool, patchArgs, {
    stdio: "inherit",
  });

  if (patchProcess.error) {
    console.error(`Failed to patch binary: ${patchProcess.error}`);
    process.exit(1);
  } else if (patchProcess.status !== 0) {
    console.error(
      `Failed to patch binary: ${patchTool} exited with code ${patchProcess.status}`
    );
    process.exit(1);
  } else {
    console.log("Binary patched successfully.");
  }
}

/*
If we're using a host->target configuration other than linux->win32, run the above functions to
build capnproto and `capnp.node`, then move `capnp.node` to the expected location.

In the linux->win32 case, we're stuck using a precompiled binary, because (speaking from hard
experience) `node-gyp` doesn't support that type of cross-compilation. We simply copy it from our
`prebuilt/win32-x64` subdirectory.
*/

if (process.platform === "linux" && args.targetPlatform === "win32") {
  const prebuiltPath = "prebuilt/win32-x64/capnp.node";

  console.log(`Using prebuilt binary ${prebuiltPath}...`);

  moveBuildResult(prebuiltPath, buildEnvironment);
} else {
  build(buildEnvironment);

  const builtPath = path.join(
    __dirname,
    "build",
    args.debug ? "Debug" : "Release",
    "capnp.node"
  );

  moveBuildResult(builtPath, buildEnvironment);
}
