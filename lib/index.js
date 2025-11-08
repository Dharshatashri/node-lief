/**
 * LIEF Node.js Bindings
 *
 * This is the main JavaScript entry point that loads the native addon
 * and exports the LIEF API for use from JavaScript/TypeScript.
 */

const { existsSync } = require('node:fs');
const { platform } = require('node:os');
const { join } = require('node:path');

const binding = process.versions.bun
  ? require(
      `../prebuilds/${process.platform}-${process.arch}/node-lief${process.libc ? '.' + process.libc : ''}.node`
    )
  : require('node-gyp-build')(join(__dirname, '..'));

// Export the binding directly - it already has the proper structure
module.exports = binding;
