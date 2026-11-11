// Write lib/scanner/fund.json from public/data/guide.json: each GitHub Secure Open Source Fund repository, its
// sessions, and the team's primary posts about the program. The scanner credits people-security-training and
// people-share-learnings from it. Run `npm run fund` after rebuilding the guide; a test fails until the two agree.
import { readFileSync, writeFileSync } from 'node:fs';
import { fundFromGuide } from '../lib/fund-data.ts';

const guide = JSON.parse(readFileSync(new URL('../public/data/guide.json', import.meta.url), 'utf8'));
const out = new URL('../lib/scanner/fund.json', import.meta.url);
const fund = fundFromGuide(guide);
writeFileSync(out, JSON.stringify(fund, null, 1) + '\n');
console.log(`lib/scanner/fund.json: ${fund.repos.length} repositories`);
