/**
 * Markdown to HTML for the site's text pages (content/, through lib/pages.ts). It covers what those pages use and
 * nothing more:
 * - headings (# to ####), with an id from their text on ## and below, so a section can be linked;
 * - paragraphs;
 * - lists ("- " or "1. "), one level deep, one line per item;
 * - fenced code blocks (```lang), drawn like the code snippets on the home page;
 * - pipe tables with a header row, whose first column heads each row (no | inside a cell);
 * - `code` spans and [links](url), the only inline markup.
 * Anything else stays plain text, and all text is escaped, so a page can't carry HTML of its own. Links may only point
 * at this site, http(s) or mailto. Written this way, the files are also plain CommonMark (GFM for the tables), so the
 * source itself is the page's Markdown version.
 */

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ESCAPES[c]);
}

/** `code`, or [text](url). */
const INLINE = /`([^`]+)`|\[([^\]]+)\]\(([^()\s]+)\)/g;
const FENCE = /^```([\w+-]*)\s*$/;
const FENCE_END = /^```\s*$/;
const HEADING = /^(#{1,4}) +(.+?) *$/;
const BULLET = /^- +(.+)$/;
const NUMBERED = /^\d+\. +(.+)$/;
const TABLE_RULE = /^\|? *:?-{3,}:? *(\| *:?-{3,}:? *)*\|? *$/;

/** A link target a page may use: a path on this site, a #fragment, http(s) or mailto. Anything else isn't linked. */
function safeHref(url: string): string | null {
  return /^(?:https?:\/\/|mailto:|\/(?![/\\])|#)/i.test(url) ? url : null;
}

/** One line of text with its inline markup. */
export function renderInline(text: string): string {
  let html = '';
  let at = 0;
  for (const m of text.matchAll(INLINE)) {
    html += escapeHtml(text.slice(at, m.index));
    if (m[1] !== undefined) {
      html += `<code translate="no">${escapeHtml(m[1])}</code>`;
    } else {
      const href = safeHref(m[3]);
      const label = renderInline(m[2]);
      html += href ? `<a href="${escapeHtml(href)}">${label}</a>` : label;
    }
    at = m.index + m[0].length;
  }
  return html + escapeHtml(text.slice(at));
}

/** The text a reader sees, without the markup: for heading ids and the page's title. */
export function plainText(text: string): string {
  return text.replace(INLINE, (_whole, code: string | undefined, label: string) => code ?? plainText(label));
}

function slug(text: string): string {
  return plainText(text)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function cells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((cell) => cell.trim());
}

function table(head: string[], rows: string[][]): string {
  const th = head.map((cell) => `<th scope="col">${renderInline(cell)}</th>`).join('');
  const body = rows.map(
    ([first = '', ...rest]) =>
      `<tr><th scope="row">${renderInline(first)}</th>${rest.map((cell) => `<td>${renderInline(cell)}</td>`).join('')}</tr>`,
  );
  return `<table>\n<thead><tr>${th}</tr></thead>\n<tbody>\n${body.join('\n')}\n</tbody>\n</table>`;
}

/** The look of the home page's snippets (core.css), without its Copy button, which needs JavaScript. */
function codeBlock(code: string, lang: string): string {
  const bar = lang ? `<div class="sg-code__bar"><span>${escapeHtml(lang)}</span></div>` : '';
  // tabindex lets keyboard users scroll a long line, as on the home page.
  return `<div class="sg-code">${bar}<pre tabindex="0"><code translate="no">${escapeHtml(code)}</code></pre></div>`;
}

function startsBlock(line: string, next: string | undefined): boolean {
  return (
    FENCE.test(line) ||
    HEADING.test(line) ||
    BULLET.test(line) ||
    NUMBERED.test(line) ||
    (line.startsWith('|') && TABLE_RULE.test(next ?? ''))
  );
}

/** A whole document. */
export function renderMarkdown(markdown: string): string {
  const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
  const html: string[] = [];
  const ids = new Set<string>();
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i += 1;
      continue;
    }

    const fence = FENCE.exec(line);
    if (fence) {
      const code: string[] = [];
      for (i += 1; i < lines.length && !FENCE_END.test(lines[i]); i += 1) code.push(lines[i]);
      i += 1; // the closing fence
      html.push(codeBlock(code.join('\n'), fence[1]));
      continue;
    }

    const heading = HEADING.exec(line);
    if (heading) {
      const level = heading[1].length;
      let id = level > 1 ? slug(heading[2]) : '';
      if (id) {
        const base = id;
        for (let n = 2; ids.has(id); n += 1) id = `${base}-${n}`;
        ids.add(id);
      }
      html.push(`<h${level}${id ? ` id="${id}"` : ''}>${renderInline(heading[2])}</h${level}>`);
      i += 1;
      continue;
    }

    if (line.startsWith('|') && TABLE_RULE.test(lines[i + 1] ?? '')) {
      const head = cells(line);
      const rows: string[][] = [];
      for (i += 2; i < lines.length && lines[i].startsWith('|'); i += 1) rows.push(cells(lines[i]));
      html.push(table(head, rows));
      continue;
    }

    const list = BULLET.test(line) ? BULLET : NUMBERED.test(line) ? NUMBERED : null;
    if (list) {
      const items: string[] = [];
      for (let m = list.exec(lines[i]); m; m = i < lines.length ? list.exec(lines[i]) : null) {
        items.push(`<li>${renderInline(m[1])}</li>`);
        i += 1;
      }
      const tag = list === BULLET ? 'ul' : 'ol';
      html.push(`<${tag}>\n${items.join('\n')}\n</${tag}>`);
      continue;
    }

    const paragraph = [line.trim()];
    for (i += 1; i < lines.length && lines[i].trim() && !startsBlock(lines[i], lines[i + 1]); i += 1) {
      paragraph.push(lines[i].trim());
    }
    html.push(`<p>${renderInline(paragraph.join(' '))}</p>`);
  }
  return html.join('\n');
}
