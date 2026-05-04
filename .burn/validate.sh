#!/bin/bash
set -e
cd "$(dirname "$0")/.."
npm run lint
npm run build
npm run test
