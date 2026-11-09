/**
 * Which GitHub repos have an OSS-Fuzz project, so the scanner can credit continuous fuzzing.
 * The list ships with the site (lib/ossfuzz.json). A long-running server (`next start`) also refreshes its own copy
 * when that copy is more than a day old; a serverless function just uses the shipped one.
 */
import fs from 'node:fs';
import path from 'node:path';
import { cacheDir, envToken, onVercel } from './env.ts';
import { buildIndex, type OssFuzzIndex } from './ossfuzz-build.ts';
import shipped from './ossfuzz.json';

const REFRESH_AFTER = 86_400;
let index: OssFuzzIndex | null = null;
let refreshing = false;

function cachedFile(): string {
  return path.join(cacheDir(), 'ossfuzz.json');
}

function stale(file: string): boolean {
  try {
    return Date.now() / 1000 - fs.statSync(file).mtimeMs / 1000 > REFRESH_AFTER;
  } catch {
    return true;
  }
}

async function refresh(file: string): Promise<void> {
  try {
    const fresh = await buildIndex(envToken()); // 2 API calls: the operator's GITHUB_TOKEN, or none
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(`${file}.tmp`, JSON.stringify(fresh));
    fs.renameSync(`${file}.tmp`, file);
    index = fresh;
  } catch (e) {
    console.log('oss-fuzz index refresh failed:', (e as Error).message); // best effort: the current list stays in use
  } finally {
    refreshing = false;
  }
}

/** The freshest list available: this server's own refreshed copy if there is one, else the shipped one. */
export function ossFuzzIndex(): OssFuzzIndex {
  if (!index) {
    const file = cachedFile();
    try {
      index = JSON.parse(fs.readFileSync(file, 'utf8')) as OssFuzzIndex;
    } catch {
      index = shipped as OssFuzzIndex;
    }
    // Only a long-running production server refreshes: not tests, not `next dev`, not a serverless function.
    if (process.env.NODE_ENV === 'production' && !onVercel() && !refreshing && stale(file)) {
      refreshing = true;
      void refresh(file);
    }
  }
  return index;
}

export function ossFuzzLookup(repo: string): string[] {
  return ossFuzzIndex()[repo.toLowerCase()] || [];
}
