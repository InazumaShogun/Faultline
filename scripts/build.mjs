import { cp, mkdir, copyFile } from 'node:fs/promises';
await mkdir('dist/public/assets', { recursive: true });
await cp('public', 'dist/public', { recursive: true });
await copyFile('dist/src/web/app.js', 'dist/public/assets/app.js');
await cp('examples', 'dist/examples', { recursive: true });
console.log('Faultline built. Start with: node dist/src/server.js');
