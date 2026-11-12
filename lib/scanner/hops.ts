// One hop from a workflow step into what it runs (new in 0.5.0): a package.json script (npm run X, pnpm run X,
// yarn X, bun run X) or a Makefile target (make X). Each file is read once, and only when a step needs it.
import { re, search, splitLines } from './py.ts';

/**
 * A package.json script or Makefile target run from a step: the tool and the name. An option is -[\w-]+, the same as
 * -{1,2}[\w-]+, which could read "--a" two ways and so took time doubling with each option on a line that didn't match.
 */
export const SCRIPT_RUN = re(
  String.raw`(?:^|[\s;&|(])(npm\s+run(?:-script)?|pnpm\s+run|yarn\s+run|bun\s+run|pnpm|yarn|make)` +
    String.raw`(?:\s+-[\w-]+(?:=\S+)?)*\s+([A-Za-z0-9_][\w:.-]*)`,
);
/** A step that runs the package.json script named publish: npm run publish, pnpm run publish or yarn run publish. */
export const PUBLISH_SCRIPT_RUN = re(String.raw`\b(?:npm|pnpm|yarn)\s+run\s+publish(?![\w:.-])`);
/**
 * What a package.json script must run to publish to npm: npm's or pnpm's publish (staged too), yarn npm publish, or a
 * tool that publishes (changesets, semantic-release, np, release-it, lerna publish). A dry run doesn't count: its
 * flag is looked for in the 200 characters after the command. Options as in SCRIPT_RUN.
 */
export const NPM_PUBLISH = re(
  String.raw`(?:^|[\s;&|(])(?:(?:npm|pnpm)(?:\s+-[\w-]+(?:=\S+)?)*\s+(?:stage\s+)?publish\b|yarn\s+npm\s+publish\b|` +
    String.raw`changesets?\s+publish\b|semantic-release\b|(?:npx\s+)?np(?=\s|$)|release-it\b|lerna\s+publish\b)` +
    String.raw`(?![^\n]{0,200}\s--dry-run\b)`,
);

/** Whether a package.json script publishes to npm (see NPM_PUBLISH). */
export function publishesToNpm(script: string): boolean {
  return search(NPM_PUBLISH, script) !== null;
}

/** A Makefile rule's first line: its targets, then one or two colons (not := or ::=, which assign). */
const MAKE_TARGET = re(String.raw`^([A-Za-z0-9_][\w.-]*(?:\s+[A-Za-z0-9_][\w.-]*)*)\s*::?(?!=)`);

/** A Makefile's lines, and the line each target is first named on. */
interface Makefile {
  lines: string[];
  at: Map<string, number>;
  /** Each rule's body, by the line of the rule. */
  bodies: Map<number, string>;
}

export class Hops {
  private files: Set<string>;
  private read: (path: string) => Promise<string | null>;
  private pkg: Promise<Record<string, unknown> | null> | null = null;
  private make: Promise<Makefile | null> | null = null;

  constructor(files: string[], read: (path: string) => Promise<string | null>) {
    this.files = new Set(files);
    this.read = read;
  }

  private scripts(): Promise<Record<string, unknown> | null> {
    this.pkg ??= this.files.has('package.json')
      ? this.read('package.json').then((t) => {
          try {
            const s = t === null ? null : JSON.parse(t)?.scripts;
            return s && typeof s === 'object' && !Array.isArray(s) ? (s as Record<string, unknown>) : null;
          } catch {
            return null;
          }
        })
      : Promise.resolve(null);
    return this.pkg;
  }

  /**
   * The Makefile, read once, with where each target's rule is. Looking for the target line by line on each question
   * took time squared on a workflow that runs thousands of targets.
   */
  private makefile(): Promise<Makefile | null> {
    if (!this.make) {
      const f = ['GNUmakefile', 'makefile', 'Makefile'].find((p) => this.files.has(p));
      this.make = f
        ? this.read(f).then((t) => {
            if (t === null) return null;
            const lines = splitLines(t);
            const at = new Map<string, number>();
            lines.forEach((l, k) => {
              for (const name of (search(MAKE_TARGET, l)?.[1] ?? '').split(' ')) if (!at.has(name)) at.set(name, k);
            });
            return { lines, at, bodies: new Map() };
          })
        : Promise.resolve(null);
    }
    return this.make;
  }

  /**
   * The body of the script or target a command runs ("make", "npm", "pnpm", "yarn" or "bun", and its name): its
   * text, null when the file has no such script or target, or undefined when there's no file to look in.
   */
  async body(tool: string, target: string): Promise<string | null | undefined> {
    if (tool === 'make') {
      const make = await this.makefile();
      if (!make) return undefined;
      const { lines } = make;
      const at = make.at.get(target);
      if (at === undefined) return null;
      let got = make.bodies.get(at);
      if (got === undefined) {
        const body: string[] = [];
        for (let k = at + 1; k < lines.length && (lines[k].startsWith('\t') || lines[k].trim() === ''); k++) {
          body.push(lines[k]);
        }
        make.bodies.set(at, (got = body.join('\n')));
      }
      return got;
    }
    const s = await this.scripts();
    if (!s) return undefined;
    return typeof s[target] === 'string' ? (s[target] as string) : null;
  }
}
