/**
 * Refresh the OSS-Fuzz list the site ships (lib/ossfuzz.json). Run from the repo root with `npm run ossfuzz`.
 * It's an operator's script, so for its two API calls it takes your token the way the scanner CLI does:
 * GITHUB_TOKEN, GH_TOKEN, then `gh auth token`. The server itself never does that.
 */
import { writeFileSync } from 'node:fs';
import { buildIndex, formatIndex } from '../lib/ossfuzz-build.ts';
import { findToken } from '../lib/scanner/index.ts';

const out = new URL('../lib/ossfuzz.json', import.meta.url);
const index = await buildIndex(findToken());
writeFileSync(out, formatIndex(index));
console.error(`wrote ${Object.keys(index).length} repos to ${out.pathname}`);
