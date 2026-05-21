#!/bin/bash
set -e
cd "$(dirname "$0")/.."
# Agent runs can leave node_modules incomplete (modified package.json without
# a matching install, or partial uninstall). Without a check the next validate
# fails fast with exit 127 because eslint/tsc/vitest binaries are missing.
if [ ! -x node_modules/.bin/eslint ] || [ ! -x node_modules/.bin/tsc ] || [ ! -x node_modules/.bin/vitest ]; then
  npm install --no-audit --no-fund
fi
npm run lint
npm run build
npm run test
