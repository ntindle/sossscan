/**
 * sosf-scan: a security self-check for a GitHub repository.
 *
 * Built from what the 190+ projects in GitHub's Secure Open Source Fund actually changed.
 *
 * Runs entirely on your machine and is read-only: it only sends GET requests to GitHub
 * (api.github.com, raw.githubusercontent.com, github.com) and two public score services
 * (api.securityscorecards.dev, www.bestpractices.dev). Nothing is uploaded anywhere.
 * Private repos are never looked up in Scorecard, the Best Practices badge, OSS-Fuzz or OSS Scanner.
 *
 * Usage:
 *   node sosf-scan.mjs OWNER/REPO [--out report.json] [--public] [--token TOKEN] [--quiet]
 *
 * Token (optional, recommended): --token, $GITHUB_TOKEN, $GH_TOKEN, or `gh auth token`. --public uses none of them
 * unless you pass --token, so it sees what anyone would.
 * With a token that has admin access to the repo, the private layer also checks settings only
 * admins can see: secret scanning, push protection, Dependabot alerts, Actions permissions,
 * fork-PR approval, rulesets, immutable releases, environments, org 2FA, open alert backlogs.
 *
 * Load the JSON report into the guide site ("Load private report"); it is parsed in your browser.
 * Requires Node 20 or newer, no dependencies.
 */
import { realpathSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { findToken } from './http.ts';
import { pyStr, pyStrip, re, search } from './py.ts';
import { scan } from './scan.ts';
import type { Status } from './types.ts';

const ICON: Record<Status, string> = {
  pass: 'PASS',
  warn: 'WARN',
  fail: 'FAIL',
  info: 'info',
  unknown: ' ?? ',
  na: ' -- ',
};
const ORDER: Status[] = ['fail', 'warn', 'unknown', 'pass', 'info', 'na'];
/**
 * OWNER/REPO, alone or at the end of a URL such as https://github.com/OWNER/REPO.git or git@github.com:OWNER/REPO.
 * GitHub names are ASCII letters, digits, ".", "_" and "-", and OWNER starts the argument or follows "/" or ":", so
 * an argument with any other character in the names is refused rather than cut down to a different repo.
 */
const REPO_ARG = re(String.raw`(?:^|[/:])([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$`);

const OPTIONS = {
  out: { type: 'string' },
  token: { type: 'string' },
  public: { type: 'boolean' },
  quiet: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
} as const;
type OptionName = keyof typeof OPTIONS;

function prog(): string {
  return basename(process.argv[1] ?? 'sosf-scan.mjs');
}

function usage(): string {
  return `usage: ${prog()} [-h] [--out OUT] [--token TOKEN] [--public] [--quiet] repo\n`;
}

function help(): string {
  return `${usage()}
Security self-check for a GitHub repository (read-only).

positional arguments:
  repo           OWNER/REPO or a GitHub URL

options:
  -h, --help     show this help message and exit
  --out OUT      write the JSON report here (default: sosf-report-OWNER-
                 REPO.json)
  --token TOKEN  GitHub token (default: $GITHUB_TOKEN, $GH_TOKEN or \`gh auth
                 token\`)
  --public       only run checks anyone can see, without a token unless
                 --token is given
  --quiet
`;
}

class UsageError extends Error {}

/** argparse lets any unambiguous prefix of a long option stand for it (--pub for --public). */
function expandAbbreviations(argv: string[]): string[] {
  const names = Object.keys(OPTIONS);
  const out: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') {
      out.push(...argv.slice(i));
      break;
    }
    const m = /^--([^=]+)(=.*)?$/s.exec(arg);
    if (m && !names.includes(m[1])) {
      const hits = names.filter((n) => n.startsWith(m[1]));
      if (hits.length > 1) {
        throw new UsageError(`ambiguous option: --${m[1]} could match ${hits.map((h) => '--' + h).join(', ')}`);
      }
      if (hits.length === 1) {
        out.push(`--${hits[0]}${m[2] ?? ''}`);
        continue;
      }
    }
    out.push(arg);
  }
  return out;
}

interface Args {
  repo: string;
  out?: string;
  token?: string;
  public: boolean;
  quiet: boolean;
}

/** Parse argv like the Python scanner's argparse parser. Returns null when help was printed. */
function parse(argv: string[]): Args | null {
  const args = expandAbbreviations(argv);
  const { tokens } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: false, tokens: true });
  const values: Partial<Record<OptionName, string | boolean>> = {};
  const positionals: string[] = [];
  const extras: string[] = [];
  for (const t of tokens) {
    if (t.kind === 'positional') {
      if (positionals.length) extras.push(t.value);
      else positionals.push(t.value);
    } else if (t.kind === 'option') {
      if (!Object.hasOwn(OPTIONS, t.name)) {
        extras.push(args[t.index]);
        continue;
      }
      const name = t.name as OptionName;
      if (name === 'help') {
        process.stdout.write(help());
        return null;
      }
      if (OPTIONS[name].type === 'string') {
        // argparse won't take a value that looks like another option.
        if (t.value === undefined || (!t.inlineValue && /^-./.test(t.value) && !/^-\d+$|^-\d*\.\d+$/.test(t.value))) {
          throw new UsageError(`argument --${name}: expected one argument`);
        }
        values[name] = t.value;
      } else {
        if (t.inlineValue) throw new UsageError(`argument --${name}: ignored explicit argument '${t.value}'`);
        values[name] = true;
      }
    }
  }
  if (!positionals.length) throw new UsageError('the following arguments are required: repo');
  if (extras.length) throw new UsageError(`unrecognized arguments: ${extras.join(' ')}`);
  return {
    repo: positionals[0],
    out: values.out as string | undefined,
    token: values.token as string | undefined,
    public: values.public === true,
    quiet: values.quiet === true,
  };
}

/** The parsed arguments and OWNER/REPO, or the exit code when there is nothing to scan (help or a usage error). */
function parseOrExit(argv: string[]): { a: Args; repo: string } | number {
  try {
    const a = parse(argv);
    if (!a) return 0;
    const m = search(REPO_ARG, pyStrip(a.repo));
    // "." and ".." aren't names either: in the API path they'd point somewhere else.
    if (!m || ['.', '..'].includes(m[1]) || ['.', '..'].includes(m[2])) throw new UsageError('expected OWNER/REPO');
    return { a, repo: `${m[1]}/${m[2]}` };
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    process.stderr.write(`${usage()}${prog()}: error: ${e.message}\n`);
    return 2;
  }
}

/** The CLI: scan a repo, write the JSON report, print a summary table. Returns the exit code. */
export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const parsed = parseOrExit(argv);
  if (typeof parsed === 'number') return parsed;
  const { a, repo } = parsed;
  // --public scans as anyone would, so it leaves out the token this machine has (a --token still counts).
  const anonymous = a.public && !a.token;
  const token = anonymous ? null : findToken(a.token);
  const log = a.quiet ? () => {} : (msg: string) => void process.stderr.write(msg + '\n');
  if (anonymous) {
    log(
      '--public: scanning without a token, as anyone would see it ' +
        '(GitHub allows 60 requests an hour; pass --token to raise that)',
    );
  } else if (!token) {
    log(
      'no token found: running the public checks only, at 60 requests an hour. ' +
        'Set GITHUB_TOKEN, pass --token, or sign in with `gh auth login`',
    );
  }
  const rep = await scan(repo, { token, layer: a.public ? 'public' : 'private', log });
  const out = a.out || `sosf-report-${repo.replaceAll('/', '-')}.json`;
  writeFileSync(out, JSON.stringify(rep, null, 1));
  if (!a.quiet) {
    const lines: string[] = [];
    const rows = Object.entries(rep.results).sort(([, x], [, y]) => ORDER.indexOf(x.status) - ORDER.indexOf(y.status));
    for (const [itemId, r] of rows) lines.push(`[${ICON[r.status]}] ${itemId.padEnd(32)} ${r.summary}`);
    const hi = rep.findings.filter((f) => f.severity === 'high');
    if (hi.length) {
      lines.push(`\n${hi.length} high-severity finding(s):`);
      for (const f of hi.slice(0, 15)) lines.push(`  - ${f.title} (${pyStr(f.path)}:${pyStr(f.line)})`);
    }
    lines.push(`\nReport written to ${out}. Load it into the guide site to see fixes (it stays in your browser).`);
    process.stdout.write(lines.join('\n') + '\n');
  }
  return !rep.errors.length || Object.keys(rep.results).length ? 0 : 1;
}

function runningAsScript(): boolean {
  try {
    return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (runningAsScript()) {
  main().then((code) => {
    process.exitCode = code;
  });
}
