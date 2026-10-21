#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
node -e "if(Number(process.versions.node.split('.')[0])<24){console.error('Node.js 24 or later is required.');process.exit(1)}"
if [ ! -f dist/src/server.js ]; then
  npm ci --ignore-scripts --no-fund
  npm run build
fi
printf '\nOpen http://127.0.0.1:4317 in your browser. Press Ctrl+C to stop.\n\n'
exec node dist/src/server.js
