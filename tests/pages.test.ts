/**
 * The text pages (lib/pages.ts, content/) and the home page's trust signals: each page is served as HTML with real
 * text, the site's links in its footer, structured data that parses, and the same security headers as the rest.
 */
import fs from 'node:fs';
import path from 'node:path';
import { getPathMatch } from 'next/dist/shared/lib/router/utils/path-match.js';
import { describe, expect, it } from 'vitest';
import { renderInline, renderMarkdown } from '@/lib/markdown.ts';
import { markdownPath } from '@/lib/negotiate.ts';
import {
  AUTHOR_URL,
  FOOTER_LINKS,
  footerHtml,
  PAGES,
  pageHtml,
  pageMarkdown,
  pageTitle,
  REPO_URL,
  SITE,
} from '@/lib/pages.ts';
import config, { CSP, SECURITY_HEADERS, TEXT_PAGES } from '@/next.config.ts';
import { Browser } from './helpers.ts';

const ROOT = process.cwd();
const read = (file: string) => fs.readFileSync(path.join(ROOT, file), 'utf8');
const INDEX = read('public/index.html');
const PATHS = PAGES.map((p) => p.path);
const TRUST = ['/about', '/contact', '/privacy'];

/** What a reader sees of the page's content: the text in <main>, without the markup. */
function visibleText(html: string): string {
  const entities: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" };
  return (/<main\b[^>]*>([\s\S]*?)<\/main>/.exec(html)?.[1] ?? '')
    .replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&(amp|lt|gt|quot|#39);/g, (_m, name: string) => entities[name])
    .replace(/\s+/g, ' ')
    .trim();
}

function jsonLd(html: string): any[] {
  return [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map((m) => JSON.parse(m[1]));
}

function footerOf(html: string): string {
  return /<footer\b[\s\S]*?<\/footer>/.exec(html)?.[0] ?? '';
}

/** Every key anywhere in a JSON value. */
function keysOf(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(keysOf);
  if (value && typeof value === 'object') {
    return Object.entries(value).flatMap(([k, v]) => [k, ...keysOf(v)]);
  }
  return [];
}

describe('the text pages', () => {
  it.each(PATHS)('serves %s as an HTML page', async (urlPath) => {
    const res = await new Browser().get(urlPath);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8');
    const html = await res.text();
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain(`<title>${pageTitle(urlPath)}</title>`);
    expect(html).toContain('<link rel="stylesheet" href="/shared/core.css">');
  });

  it.each(TRUST)('gives %s at least 500 characters of text to read', (urlPath) => {
    expect(visibleText(pageHtml(urlPath)).length).toBeGreaterThanOrEqual(500);
  });

  it.each([
    ['/docs/api', 'sossscan API'],
    ['/docs/cli', 'sossscan CLI'],
  ])('names the product and the tool in the title and heading of %s', (urlPath, name) => {
    const html = pageHtml(urlPath);
    expect(/<title>([^<]*)<\/title>/.exec(html)?.[1]).toContain(name);
    expect(/<h1>([\s\S]*?)<\/h1>/.exec(html)?.[1]).toContain(name);
  });

  it('starts each page with its heading, which is also its title', () => {
    expect(PAGES.map((p) => pageTitle(p.path))).toEqual([
      'About sossscan',
      'Contact · sossscan',
      'Privacy · sossscan',
      'sossscan docs',
      'sossscan API',
      'sossscan CLI',
      'sossscan for AI agents',
    ]);
    for (const page of PAGES) {
      expect(pageMarkdown(page.path)).toMatch(/^# \S/);
      expect(pageHtml(page.path).match(/<h1>/g)).toHaveLength(1);
      expect(page.description.length).toBeGreaterThan(40);
    }
  });

  it('links the docs overview to the API and the CLI, and those back to each other', () => {
    expect(pageHtml('/docs')).toContain('href="/docs/api"');
    expect(pageHtml('/docs')).toContain('href="/docs/cli"');
    expect(pageHtml('/docs/api')).toContain('href="/docs/cli"');
    expect(pageHtml('/docs/cli')).toContain('href="/docs/api#the-report"');
  });

  it('only links to pages and files that exist, and to sections that exist', () => {
    const pages = new Map(PAGES.map((p) => [p.path, pageHtml(p.path)]));
    pages.set('/', INDEX);
    // Routes that aren't pages: each page's Markdown twin, and the sitemap.
    const routes = new Set([...[...pages.keys()].map(markdownPath), '/sitemap.xml']);
    for (const [from, html] of pages) {
      for (const [, target] of html.matchAll(/\b(?:href|src)="((?:\/|#)[^"]*)"/g)) {
        const [where, section] = target.split('#');
        const to = where || from;
        if (!pages.has(to) && !routes.has(to)) {
          expect(fs.existsSync(path.join(ROOT, 'public', to)), `${from} links ${target}`).toBe(true);
        }
        if (section) expect(pages.get(to), `${from} links ${target}`).toContain(`id="${section}"`);
      }
    }
  });

  it('runs no inline script, so the CSP needs no hashes for them', () => {
    expect(CSP).toContain("script-src 'self'"); // /shared/theme.js
    for (const page of PAGES) {
      const scripts = [...pageHtml(page.path).matchAll(/<script\b([^>]*)>/gi)].map((m) => m[1].trim());
      expect(scripts).toEqual(['src="/shared/theme.js"', 'type="application/ld+json"']);
    }
  });

  it('describes each page in JSON-LD', () => {
    for (const page of PAGES) {
      expect(jsonLd(pageHtml(page.path))).toEqual([
        {
          '@context': 'https://schema.org',
          '@type': page.type,
          name: pageTitle(page.path),
          description: page.description,
          url: `${SITE}${page.path}`,
          isPartOf: { '@type': 'WebSite', name: 'sossscan', url: `${SITE}/` },
        },
      ]);
    }
  });

  it('gives JSON examples that parse', () => {
    let examples = 0;
    for (const page of PAGES) {
      for (const m of pageMarkdown(page.path).matchAll(/```json\n([\s\S]*?)\n```/g)) {
        expect(() => JSON.parse(m[1])).not.toThrow();
        examples += 1;
      }
    }
    expect(examples).toBeGreaterThanOrEqual(2);
  });
});

describe('the facts on the pages', () => {
  const guide = JSON.parse(read('public/data/guide.json'));
  const about = pageMarkdown('/about');

  it("states the guide's numbers as guide.json has them", () => {
    const layer = (id: string) => guide.items.filter((i: { layer: string }) => i.layer === id).length;
    for (const phrase of [
      `${guide.items.length} checks`,
      `${guide.counts.teams} projects`,
      `${guide.counts.posts} posts`,
      `${guide.counts.claims} claims`,
      `covers ${layer('public')} of the checks`,
      `covers ${layer('private')} more`,
      `other ${layer('manual')} are`,
    ]) {
      expect(about).toContain(phrase);
    }
    expect(Object.keys(guide.app_fixes)).toHaveLength(9);
    expect(about).toContain('nine settings in one click');
    expect(guide.stages.map((s: { id: string }) => s.id)).toEqual([
      'accounts',
      'repo',
      'code',
      'ci',
      'deps',
      'release',
      'disclosure',
      'response',
      'people',
    ]);
    const api = pageMarkdown('/docs/api');
    expect(api).toContain(`the ${guide.items.length} checks`);
    expect(api).toContain(`the ${guide.counts.teams} Fund projects`);
  });

  it('gives the rate limits that lib/limits.ts sets', () => {
    const limits = read('lib/limits.ts');
    const [, perMinute, perHour] = /scan: \[\s*\[60, (\d+)\],\s*\[3600, (\d+)\],?\s*\]/.exec(limits)!;
    const [, app] = /app: \[\[60, (\d+)\]\]/.exec(limits)!;
    expect(pageMarkdown('/docs/api')).toContain(`${perMinute} scan requests a minute and ${perHour} an hour`);
    expect(pageMarkdown('/privacy')).toContain(
      `${perMinute} scan requests a minute and ${perHour} an hour, and ${app} sign-in and app requests a minute`,
    );
  });

  it('documents every option the CLI has', () => {
    const options = /const OPTIONS = \{([\s\S]*?)\} as const;/.exec(read('lib/scanner/cli.ts'))![1];
    const names = [...options.matchAll(/^\s*(\w+): \{/gm)].map((m) => m[1]);
    expect(names).toEqual(['out', 'token', 'public', 'quiet', 'help']);
    for (const name of names) expect(pageMarkdown('/docs/cli')).toContain(`--${name}`);
  });
});

describe('the footer', () => {
  it('has the site links in the HTML of every page, the home page included', () => {
    expect(FOOTER_LINKS).toEqual([
      ['About', '/about'],
      ['Contact', '/contact'],
      ['Privacy', '/privacy'],
      ['Docs', '/docs'],
      ['GitHub', REPO_URL],
    ]);
    for (const html of [INDEX, ...PATHS.map(pageHtml)]) {
      const foot = footerOf(html);
      for (const [label, href] of FOOTER_LINKS) expect(foot).toMatch(new RegExp(`<a href="${href}"[^>]*>${label}</a>`));
      expect(foot).toContain(`<a href="${AUTHOR_URL}">`);
    }
  });

  it('is the same on the home page as on the text pages, before any script runs', () => {
    expect(footerOf(INDEX)).toBe(footerHtml('/'));
    // pipeline.js adds its line above the links rather than replacing them.
    expect(read('public/pipeline/pipeline.js')).toContain("$('#foot').prepend(");
  });

  it('marks the page you are on', () => {
    expect(footerOf(pageHtml('/privacy'))).toContain('<a href="/privacy" aria-current="page">Privacy</a>');
    expect(footerOf(pageHtml('/docs/api'))).not.toContain('aria-current');
  });
});

describe("the home page's JSON-LD", () => {
  const blocks = jsonLd(INDEX);
  const graph: any[] = blocks[0]?.['@graph'] ?? [];

  it('is one block that parses, with the app and the organization behind it', () => {
    expect(blocks).toHaveLength(1);
    expect(blocks[0]['@context']).toBe('https://schema.org');
    expect(graph.map((node) => node['@type'])).toEqual(['WebApplication', 'Organization']);
  });

  it('describes the app', () => {
    const app = graph[0];
    expect(app).toMatchObject({
      name: 'sossscan',
      alternateName: 'Secure Open Source guide',
      url: `${SITE}/`,
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'Web',
      isAccessibleForFree: true,
      offers: { '@type': 'Offer', price: 0, priceCurrency: 'USD' },
      author: { '@type': 'Person', name: 'Nick Tindle', url: 'https://ntindle.com', sameAs: [AUTHOR_URL] },
      license: 'https://opensource.org/licenses/MIT',
      sameAs: [REPO_URL],
    });
    expect(app.description.length).toBeGreaterThan(50);
    expect(INDEX).toContain(`<title>${app.alternateName}</title>`); // the page's own name
  });

  it('gives a way to reach the organization, and no address', () => {
    expect(graph[1]).toMatchObject({
      name: 'sossscan',
      url: `${SITE}/`,
      email: 'sossscan@ntindle.com',
      contactPoint: { '@type': 'ContactPoint', email: 'sossscan@ntindle.com', contactType: 'customer support' },
      sameAs: [REPO_URL],
    });
    const keys = keysOf(blocks);
    expect(keys).not.toContain('address');
    expect(JSON.stringify(blocks)).not.toContain('PostalAddress');
  });
});

describe('serving the pages', () => {
  it('sends the security headers with every text page', async () => {
    const rules = await config.headers!();
    for (const urlPath of PATHS) {
      const sent = Object.fromEntries(
        rules
          .filter((rule) => getPathMatch(rule.source)(urlPath) !== false)
          .flatMap((rule) => rule.headers)
          .map((h) => [h.key, h.value]),
      );
      for (const h of SECURITY_HEADERS) expect(sent[h.key], `${h.key} on ${urlPath}`).toBe(h.value);
    }
  });

  it('prerenders each page, and keeps its Markdown in the trace in case one ever renders per request', () => {
    expect(TEXT_PAGES).toEqual(PATHS);
    for (const urlPath of PATHS) {
      expect(read(`app${urlPath}/route.ts`)).toContain("export const dynamic = 'force-static';");
      expect(config.outputFileTracingIncludes?.[urlPath]).toEqual(['./content/**/*.md']);
    }
    expect(read('Dockerfile')).toContain('COPY --from=build /srv/site/content ./content');
  });
});

describe('the Markdown renderer', () => {
  it('renders what the pages use', () => {
    const md = [
      '# A title',
      '',
      'Text with `code` and [a link](/docs).',
      'A second line of the same paragraph.',
      '## A section',
      '- one',
      '- two',
      '',
      '1. first',
      '2. second',
      '',
      '```sh',
      'echo "<hi>"',
      '```',
      '',
      '| Name | What |',
      '|---|---|',
      '| `x` | a [link](https://example.com) |',
    ].join('\n');
    expect(renderMarkdown(md)).toBe(
      [
        '<h1>A title</h1>',
        '<p>Text with <code translate="no">code</code> and <a href="/docs">a link</a>. A second line of the same paragraph.</p>',
        '<h2 id="a-section">A section</h2>',
        '<ul>\n<li>one</li>\n<li>two</li>\n</ul>',
        '<ol>\n<li>first</li>\n<li>second</li>\n</ol>',
        '<div class="sg-code"><div class="sg-code__bar"><span>sh</span></div><pre tabindex="0"><code translate="no">echo &quot;&lt;hi&gt;&quot;</code></pre></div>',
        '<table>\n<thead><tr><th scope="col">Name</th><th scope="col">What</th></tr></thead>\n<tbody>\n' +
          '<tr><th scope="row"><code translate="no">x</code></th><td>a <a href="https://example.com">link</a></td></tr>\n' +
          '</tbody>\n</table>',
      ].join('\n'),
    );
  });

  it('escapes text, and links only to this site, http(s) and mailto', () => {
    expect(renderInline('<b>&"\'</b>')).toBe('&lt;b&gt;&amp;&quot;&#39;&lt;/b&gt;');
    expect(renderInline('[x](javascript:alert)')).toBe('x');
    expect(renderInline('[x](//evil.example)')).toBe('x');
    expect(renderInline('[x](data:text/html,hi)')).toBe('x');
    expect(renderInline('[mail](mailto:a@example.com) [frag](#here)')).toBe(
      '<a href="mailto:a@example.com">mail</a> <a href="#here">frag</a>',
    );
    expect(renderInline('`<script>`')).toBe('<code translate="no">&lt;script&gt;</code>');
    expect(renderMarkdown('<script>alert(1)</script>')).toBe('<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>');
  });

  it('gives each section a unique id from its text', () => {
    expect(renderMarkdown('## The `report`\n## The report\n### What [it](/x) holds')).toBe(
      '<h2 id="the-report">The <code translate="no">report</code></h2>\n' +
        '<h2 id="the-report-2">The report</h2>\n' +
        '<h3 id="what-it-holds">What <a href="/x">it</a> holds</h3>',
    );
  });
});
