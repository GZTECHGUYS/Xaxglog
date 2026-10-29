#!/usr/bin/env node
/*
 * Fresh-clone guard.
 *
 * `react-scripts: not found` means node_modules was never installed.  npm can
 * run this pre-script before it resolves `react-scripts`, so install once and
 * let the normal start/build command continue.
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const bin = path.join(root, 'node_modules', '.bin',
  process.platform === 'win32' ? 'react-scripts.cmd' : 'react-scripts');

if (fs.existsSync(bin)) process.exit(0);

const lock = path.join(root, 'package-lock.json');
const args = fs.existsSync(lock)
  ? ['ci', '--no-audit', '--no-fund']
  : ['install', '--no-audit', '--no-fund'];

console.log('[xaxglog] frontend/node_modules is missing; installing React dependencies...');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const result = spawnSync(npm, args, { cwd: root, stdio: 'inherit', shell: false });
if (result.error) {
  console.error('[xaxglog] npm install failed:', result.error.message);
  process.exit(1);
}
if (result.status !== 0) {
  console.error('[xaxglog] npm install failed with exit code', result.status);
  process.exit(result.status || 1);
}
console.log('[xaxglog] React dependencies installed.');
