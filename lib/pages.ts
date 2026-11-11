/**
 * The site's text pages: About, Contact, Privacy, the developer docs and the page for AI agents. Each is one Markdown
 * file in content/ at its URL path (/docs/api is content/docs/api.md), written once and served two ways:
 * - pageHtml(path): the Markdown rendered by lib/markdown.ts inside the site's header and footer. The route handlers
 *   (app/about/route.ts and the rest) return it.
 * - pageMarkdown(path): the Markdown itself, at the page's Markdown twin (/about.md, from app/about.md/route.ts), and
 *   at the page's own address for requests that ask for Markdown (proxy.ts). The home page's twin is /index.md
 *   (lib/home.ts).
 * PAGES lists them all, with the description and schema.org type each one's HTML needs.
 *
 * Each of those routes answers with Vary: Accept, which caches need because one address serves both. That's why they
 * render per request instead of being prerendered: Vercel sends a prerendered route with the Vary Next.js gives it,
 * which lists Next.js's own headers and not Accept, while a route that renders per request keeps the Vary it sets.
 * The text is rendered once per server instance, and the CDN keeps each answer for a day (PAGE_CACHE_CONTROL).
 *
 * Addresses no route or file answers get notFound(), a 404 with a page in the same style, or Markdown for requests that
 * ask for it (app/[...path]/route.ts).
 *
 * The pages run no inline script. /shared/theme.js applies the saved theme, and their JSON-LD is a data block, which a
 * browser never runs, so it needs no hash in the content security policy (next.config.ts).
 */
import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from './env.ts';
import { homeMarkdown } from './home.ts';
import { escapeHtml, plainText, renderMarkdown } from './markdown.ts';
import { HTML_TYPE, MARKDOWN_TYPE, markdownPath, negotiate } from './negotiate.ts';

/** The live site. Structured data names it, as the home page's does, and canonical links point to it. */
export const SITE = 'https://sossscan.ntindle.com';
export const REPO_URL = 'https://github.com/ntindle/sossscan';
export const AUTHOR_URL = 'https://github.com/ntindle';

/** The picture link previews show (public/og.png): the site's mark and name. */
export const OG_IMAGE = {
  url: `${SITE}/og.png`,
  width: 1200,
  height: 630,
  alt: 'sossscan, the Secure Open Source guide',
};

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
      'Developer docs for sossscan: the HTTP API and the MCP server for scanning public repositories, and the CLI for scanning from your own machine.',
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
  {
    path: '/docs/mcp',
    type: 'WebPage',
    description:
      'The sossscan MCP server: let an AI agent scan public GitHub repositories and read the guide over the Model Context Protocol. Its address, tools, limits and setup for common clients.',
  },
  {
    path: '/agents',
    type: 'WebPage',
    description:
      'When an AI agent should use sossscan, how to call its API or CLI, which parts of a report matter, its limits, and what it is not for.',
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

/** The Markdown for a page or the home page (/). */
export function markdownFor(urlPath: string): string {
  return urlPath === '/' ? homeMarkdown() : pageMarkdown(urlPath);
}

function titleOf(markdown: string, where: string): string {
  const m = /^# +(.+?) *$/.exec(markdown.split('\n', 1)[0]);
  if (!m) throw new Error(`${where} must start with a # heading`);
  const heading = plainText(m[1]);
  return /sossscan/i.test(heading) ? heading : `${heading} · sossscan`;
}

/** The page's heading (its first line), which is also its title, with " · sossscan" when it doesn't name the site. */
export function pageTitle(urlPath: string): string {
  return titleOf(pageMarkdown(urlPath), `content${urlPath}.md`);
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

/**
 * What a page's head says about it besides its title: the canonical address, the Markdown twin, and the Open Graph
 * tags link previews use. public/index.html has the same for the home page, and a test keeps them equal.
 */
export function headMetadataHtml(urlPath: string, title: string, description: string): string {
  const url = `${SITE}${urlPath}`;
  return `<link rel="canonical" href="${url}">
<link rel="alternate" type="text/markdown" href="${markdownPath(urlPath)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="sossscan">
<meta property="og:title" content="${escapeHtml(title)}">
<meta property="og:description" content="${escapeHtml(description)}">
<meta property="og:url" content="${url}">
<meta property="og:image" content="${OG_IMAGE.url}">
<meta property="og:image:width" content="${OG_IMAGE.width}">
<meta property="og:image:height" content="${OG_IMAGE.height}">
<meta property="og:image:alt" content="${escapeHtml(OG_IMAGE.alt)}">
<meta name="twitter:card" content="summary_large_image">`;
}

/**
 * A whole page in the site's style: its head (the title, then `about`, the tags that describe this page, and last
 * `data`, its JSON-LD), the site's header, the Markdown as HTML, and the footer.
 */
function documentHtml({
  title,
  about,
  data,
  markdown,
  current,
}: {
  title: string;
  about: string;
  data: string;
  markdown: string;
  current: string;
}): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
${about ? `${about}\n` : ''}<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#edefea" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#1d2225" media="(prefers-color-scheme: dark)">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="stylesheet" href="/shared/core.css">
<link rel="stylesheet" href="/pipeline/pipeline.css">
<link rel="stylesheet" href="/shared/text.css">
<script src="/shared/theme.js"></script>
${data ? `${data}\n` : ''}</head>
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

${footerHtml(current)}
</body>
</html>
`;
}

/** The whole page: the site's header, the Markdown as HTML, and the footer. */
export function pageHtml(urlPath: string): string {
  const page = pageAt(urlPath);
  const markdown = pageMarkdown(urlPath);
  const title = titleOf(markdown, `content${urlPath}.md`);
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': page.type,
    name: title,
    description: page.description,
    url: `${SITE}${page.path}`,
    isPartOf: { '@type': 'WebSite', name: 'sossscan', url: `${SITE}/` },
  };
  const about = [
    `<meta name="description" content="${escapeHtml(page.description)}">`,
    headMetadataHtml(urlPath, title, page.description),
  ].join('\n');
  const data = `<script type="application/ld+json">\n${scriptJson(jsonLd)}\n</script>`;
  return documentHtml({ title, about, data, markdown, current: urlPath });
}

/** A GET handler that returns the page. */
export function pageRoute(urlPath: string): () => Response {
  pageAt(urlPath);
  return () => pageResponse(`html ${urlPath}`, HTML_TYPE, () => pageHtml(urlPath));
}

/** A GET handler for a page's Markdown twin (/about.md), or the home page's (/index.md). */
export function markdownRoute(urlPath: string): () => Response {
  if (urlPath !== '/') pageAt(urlPath);
  return () => pageResponse(`markdown ${urlPath}`, MARKDOWN_TYPE, () => markdownFor(urlPath));
}

/**
 * How long caches may keep a page. A page changes only when the site is deployed, and each deployment has its own CDN
 * cache on Vercel, so the CDN keeps an answer for a day and serves it for a week more while it fetches a new one.
 * Browsers check back each time (max-age=0).
 */
export const PAGE_CACHE_CONTROL = 'public, max-age=0, s-maxage=86400, stale-while-revalidate=604800';

/** Each page's rendered text, made on its first request: it can't change while the server runs. */
const rendered = new Map<string, string>();

function pageResponse(key: string, type: string, render: () => string): Response {
  let text = rendered.get(key);
  if (text === undefined) {
    text = render();
    rendered.set(key, text);
  }
  return new Response(text, {
    headers: { 'Content-Type': type, Vary: 'Accept', 'Cache-Control': PAGE_CACHE_CONTROL },
  });
}

/**
 * The 404 page's Markdown. It doesn't repeat the address that was asked for, so a crafted link can't put words on a
 * page of this site, for a person or for an agent reading it.
 */
export const NOT_FOUND_MARKDOWN = `# Page not found

There's no page at this address. The link may be mistyped, or the page may have moved.

- [Home page](/): scan a GitHub repository for security gaps. Its Markdown version is [/index.md](/index.md).
- [Docs](/docs): the sossscan API and CLI, and [how agents can use sossscan](/agents).
- [llms.txt](/llms.txt): an index of this site for AI agents, with links to the Markdown version of every page.
- [Sitemap](/sitemap.xml): every page on the site.
`;

export function notFoundHtml(): string {
  const title = titleOf(NOT_FOUND_MARKDOWN, 'The 404 page');
  return documentHtml({ title, about: '', data: '', markdown: NOT_FOUND_MARKDOWN, current: '' });
}

/**
 * The answer for an address nothing else serves: 404, as Markdown when the request prefers it and as HTML otherwise,
 * including when Accept rules out both (a missing page is a 404 whatever the request accepts). Nothing caches it.
 */
export function notFound(request: Request): Response {
  const markdown = negotiate(request.headers.get('accept')) === 'markdown';
  return new Response(markdown ? NOT_FOUND_MARKDOWN : notFoundHtml(), {
    status: 404,
    headers: { 'Content-Type': markdown ? MARKDOWN_TYPE : HTML_TYPE, Vary: 'Accept', 'Cache-Control': 'no-store' },
  });
}
