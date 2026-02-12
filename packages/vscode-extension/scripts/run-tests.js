const { spawnSync } = require('node:child_process');

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    ...options,
  });
  if (result.error) {
    throw result.error;
  }
  return result.status ?? 1;
}

function commandExists(command) {
  const probe = spawnSync('which', [command], { stdio: 'ignore' });
  return probe.status === 0;
}

const compileStatus = run('tsgo', ['-p', 'tsconfig.spec.json']);
if (compileStatus !== 0) {
  process.exit(compileStatus);
}

const useXvfb = process.platform === 'linux' && commandExists('xvfb-run');
if (useXvfb) {
  process.exit(run('xvfb-run', ['-a', 'node', '.vscode-test-out/runTest.js']));
}

process.exit(run('node', ['.vscode-test-out/runTest.js']));
