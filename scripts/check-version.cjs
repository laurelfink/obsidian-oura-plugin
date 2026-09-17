const assert = require('node:assert/strict');
const pkg = require('../package.json');
const manifest = require('../manifest.json');
const lock = require('../package-lock.json');
const versions = require('../versions.json');

assert.equal(manifest.version, pkg.version, 'Manifest and package versions must match');
assert.equal(lock.version, pkg.version, 'Lockfile version must match package');
assert.equal(lock.packages[''].version, pkg.version, 'Lockfile root version must match package');
assert.equal(versions[pkg.version], manifest.minAppVersion, 'versions.json must record the release minimum Obsidian version');
if (process.env.GITHUB_REF_TYPE === 'tag') {
  assert.equal(process.env.GITHUB_REF_NAME, pkg.version, 'Release tag must match the package and manifest version');
}
console.log(`Release metadata matches ${pkg.version}`);
