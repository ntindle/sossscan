/**
 * The site's text pages: About, Contact, Privacy and the developer docs. Each is one Markdown file in content/ at its
 * URL path (/docs/api is content/docs/api.md), written once and available two ways:
 * - pageHtml(path): the Markdown rendered by lib/markdown.ts inside the site's header and footer. The route handlers
 *   (app/about/route.ts and the rest) return it, prerendered at build time.
 * - pageMarkdown(path): the Markdown itself, for anything that would rather have text than a web page.
 * PAGES lists them all, with the description and schema.org type each one's HTML needs.
 *
 * The pages run no inline script. /shared/theme.js applies the saved theme, and their JSON-LD is a data block, which a
 * browser never runs, so it needs no hash in the content security policy (next.config.ts).
 */
import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from './env.ts';
import { escapeHtml, plainText, renderMarkdown } from './markdown.ts';

/** The live site. Structured data names it, as the home page's does. */
export const SITE = 'https://sossscan.ntindle.com';
export const REPO_URL = 'https://github.com/ntindle/sossscan';
export const AUTHOR_URL = 'https://github.com/ntindle';

export type Page = {
  /** Where it's served; its Markdown is content/<path>.md. */
  path: string;
  /** A sentence or two for search results and link previews. */
  description: string;
  /** Its schema.org type, for the page's JSON-LD. */
  type: 'AboutPage' | 'ContactPage' | 'WebPage';
};

export const PAGES: readonly Page[] = [
  {
    path: '/about',
    type: 'AboutPage',
    description:
      'What sossscan is and what it checks, where its guide comes from, the three ways to scan, and who made it.',
  },
  {
    path: '/contact',
    type: 'ContactPage',
    description: 'How to reach the maintainer of sossscan: email, GitHub issues, private security reports and the app.',
  },
  {
    path: '/privacy',
    type: 'WebPage',
    description:
      'What sossscan.ntindle.com does with information about you, from its code: scans, caches, rate limits, sign-in, browser storage and hosting.',
  },
  {
    path: '/docs',
    type: 'WebPage',
    description:
      'Developer docs for sossscan: the HTTP API for scanning public repositories, and the CLI for scanning from your own machine.',
  },
  {
    path: '/docs/api',
    type: 'WebPage',
    description:
      'The sossscan API: scan a public GitHub repository over HTTP and get a JSON report. Endpoints, the report format, errors and limits.',
  },
  {
    path: '/docs/cli',
    type: 'WebPage',
    description:
      'The sossscan CLI: scan a GitHub repository from your own machine with your own token, including private repositories and admin-only settings.',
  },
];

/** The footer every page has in its HTML, the home page included (public/index.html has the same links). */
export const FOOTER_LINKS: readonly [label: string, href: string][] = [
  ['About', '/about'],
  ['Contact', '/contact'],
  ['Privacy', '/privacy'],
  ['Docs', '/docs'],
  ['GitHub', REPO_URL],
];

export function findPage(urlPath: string): Page | undefined {
  return PAGES.find((p) => p.path === urlPath);
}

function pageAt(urlPath: string): Page {
  const page = findPage(urlPath);
  if (!page) throw new Error(`no text page at ${urlPath}`);
  return page;
}

/** The page's Markdown, exactly as written: it starts with the page's # heading. */
export function pageMarkdown(urlPath: string): string {
  pageAt(urlPath);
  return fs.readFileSync(path.join(ROOT, 'content', `${urlPath}.md`), 'utf8');
}

function titleOf(markdown: string, urlPath: string): string {
  const m = /^# +(.+?) *$/.exec(markdown.split('\n', 1)[0]);
  if (!m) throw new Error(`content${urlPath}.md must start with a # heading`);
  const heading = plainText(m[1]);
  return /sossscan/i.test(heading) ? heading : `${heading} · sossscan`;
}

/** The page's heading (its first line), which is also its title, with " · sossscan" when it doesn't name the site. */
export function pageTitle(urlPath: string): string {
  return titleOf(pageMarkdown(urlPath), urlPath);
}

/** JSON for inside a <script> element: "<" is escaped, so no text in it can end the element early. */
function scriptJson(data: unknown): string {
  return JSON.stringify(data, null, 2).replace(/</g, '\\u003c');
}

/** The footer for the page at `current`. public/index.html has a copy of footerHtml('/'), and a test keeps them equal. */
export function footerHtml(current: string): string {
  const links = FOOTER_LINKS.map(
    ([label, href]) => `<li><a href="${href}"${href === current ? ' aria-current="page"' : ''}>${label}</a></li>`,
  );
  return `<footer class="foot wrap" id="foot">
<nav aria-label="Site"><ul class="foot__links">
${links.join('\n')}
</ul></nav>
<p>An independent project by <a href="${AUTHOR_URL}">Nick Tindle</a>, not affiliated with GitHub.</p>
</footer>`;
}

/** The whole page: the site's header, the Markdown as HTML, and the footer. */
export function pageHtml(urlPath: string): string {
  const page = pageAt(urlPath);
  const markdown = pageMarkdown(urlPath);
  const title = titleOf(markdown, urlPath);
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': page.type,
    name: title,
    description: page.description,
    url: `${SITE}${page.path}`,
    isPartOf: { '@type': 'WebSite', name: 'sossscan', url: `${SITE}/` },
  };
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(page.description)}">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#edefea" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#1d2225" media="(prefers-color-scheme: dark)">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="stylesheet" href="/shared/core.css">
<link rel="stylesheet" href="/pipeline/pipeline.css">
<link rel="stylesheet" href="/shared/text.css">
<script src="/shared/theme.js"></script>
<script type="application/ld+json">
${scriptJson(jsonLd)}
</script>
</head>
<body>
<a class="skip" href="#main">Skip to the content</a>

<header class="bar">
  <div class="wrap bar__in">
    <a class="bar__brand" href="/">Secure Open Source guide</a>
    <button class="sg-btn sg-btn--small bar__theme" id="theme" type="button" hidden>Theme: system</button>
  </div>
</header>

<main class="wrap text" id="main">
${renderMarkdown(markdown)}
</main>

${footerHtml(urlPath)}
</body>
</html>
`;
}

/** A GET handler that returns the page. */
export function pageRoute(urlPath: string): () => Response {
  pageAt(urlPath);
  return () => new Response(pageHtml(urlPath), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
