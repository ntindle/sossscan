/**
 * The home page as Markdown, served at /index.md and to requests for / that ask for Markdown (proxy.ts). The page
 * itself is public/index.html, which draws the guide with JavaScript, so its Markdown has its own source:
 * content/index.md, which says what sossscan is and how to scan, followed by every stage and check, listed from the
 * guide's data (public/data/guide.json) so the list always matches the guide.
 */
import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from './env.ts';

type Guide = {
  stages: { id: string; label: string; blurb: string }[];
  items: { id: string; title: string; stage: string; layer: string }[];
};

/** Which scan can read a check, in the words content/index.md defines. */
const KIND: Record<string, string> = { public: 'public', private: 'admin', app: 'admin', manual: 'self-check' };

/** Every stage in order, each with its checks: title, id and which scan can read it. */
export function stagesMarkdown(guide: Guide): string {
  const lines = [
    '## Stages and checks',
    '',
    `The guide has ${guide.items.length} checks in ${guide.stages.length} stages, in the order a change meets them on its way to users, then the way problems come back.`,
  ];
  guide.stages.forEach((stage, i) => {
    const items = guide.items.filter((item) => item.stage === stage.id);
    lines.push('', `### ${i + 1}. ${stage.label}`, '', `${stage.blurb}.`, '');
    for (const item of items) {
      const kind = KIND[item.layer];
      if (!kind) throw new Error(`check ${item.id} has an unknown layer: ${item.layer}`);
      lines.push(`- ${item.title} (\`${item.id}\`, ${kind})`);
    }
  });
  return lines.join('\n') + '\n';
}

export function homeMarkdown(): string {
  const intro = fs.readFileSync(path.join(ROOT, 'content', 'index.md'), 'utf8');
  const guide: Guide = JSON.parse(fs.readFileSync(path.join(ROOT, 'public', 'data', 'guide.json'), 'utf8'));
  return `${intro.trimEnd()}\n\n${stagesMarkdown(guide)}`;
}
