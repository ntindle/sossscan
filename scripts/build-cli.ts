// Bundle the scanner CLI (lib/scanner/cli.ts) into one file people can download and run with
// `node sosf-scan.mjs OWNER/REPO`: public/download/sosf-scan.mjs (gitignored; `npm run build:cli` makes it).
// It isn't minified, so anyone can read a security tool before running it.
import { chmodSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const site = fileURLToPath(new URL('..', import.meta.url));
const entry = `${site}lib/scanner/cli.ts`;
const outfile = `${site}public/download/sosf-scan.mjs`;

// esbuild drops comments, so the usage notes at the top of cli.ts go in the banner.
const header = /^\/\*\*[\s\S]*?\*\//.exec(readFileSync(entry, 'utf8'))?.[0] ?? '';

await build({
  entryPoints: [entry],
  outfile,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  minify: false,
  legalComments: 'none',
  banner: { js: `#!/usr/bin/env node\n${header}` },
  logLevel: 'info',
});
chmodSync(outfile, 0o755);
