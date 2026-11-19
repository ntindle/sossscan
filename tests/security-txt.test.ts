/**
 * /.well-known/security.txt (lib/security-txt.ts), against RFC 9116 and against SECURITY.md and the contact page,
 * which give the same ways to report a problem. Requests go through serve() (tests/site.ts), as Next.js would.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ROOT } from '@/lib/env.ts';
import { REPO_URL, SITE } from '@/lib/pages.ts';
import { SECURITY_CONTACTS, SECURITY_TXT_PATH, securityTxt } from '@/lib/security-txt.ts';
import { serve } from './site.ts';

/** The fields RFC 9116 defines (section 2.5). */
const RFC_FIELDS = [
  'Acknowledgments',
  'Canonical',
  'Contact',
  'Encryption',
  'Expires',
  'Hiring',
  'Policy',
  'Preferred-Languages',
];
const DAY = 86_400_000;

/** Each field line as [name, value]; comments and blank lines are skipped, and anything else is an error. */
function fields(text: string): [string, string][] {
  return text
    .split('\n')
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => {
      const m = /^([A-Za-z-]+): (\S.*)$/.exec(line);
      if (!m) throw new Error(`not a security.txt field: ${line}`);
      return [m[1], m[2]];
    });
}

const values = (text: string, name: string) => fields(text).flatMap(([n, v]) => (n === name ? [v] : []));

describe('/.well-known/security.txt', () => {
  it('is plain UTF-8 text, prerendered when the site builds', async () => {
    const res = await serve(SECURITY_TXT_PATH);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/plain; charset=utf-8');
    const route = await import('@/app/.well-known/security.txt/route.ts');
    expect(route.dynamic).toBe('force-static');
  });

  it('has only the fields RFC 9116 defines: one Expires, its own address as Canonical, and the policy', async () => {
    const text = await (await serve(SECURITY_TXT_PATH)).text();
    expect(text.endsWith('\n')).toBe(true);
    for (const [name] of fields(text)) expect(RFC_FIELDS).toContain(name);
    expect(values(text, 'Expires')).toHaveLength(1);
    expect(values(text, 'Canonical')).toEqual([`${SITE}${SECURITY_TXT_PATH}`]);
    expect(values(text, 'Policy')).toEqual([`${REPO_URL}/blob/main/SECURITY.md`]);
    expect(values(text, 'Preferred-Languages')).toEqual(['en']);
  });

  it('expires at midnight UTC, under a year after the build', () => {
    const built = new Date('2026-11-18T15:30:00Z');
    const [expires] = values(securityTxt(built), 'Expires');
    expect(expires).toBe('2027-11-13T00:00:00Z');
    const ahead = Date.parse(expires) - built.getTime();
    expect(ahead).toBeGreaterThan(300 * DAY);
    expect(ahead).toBeLessThan(365 * DAY);
  });

  it('gives the ways to report that SECURITY.md and the contact page give, the private form first', () => {
    expect(values(securityTxt(new Date()), 'Contact')).toEqual([...SECURITY_CONTACTS]);
    const [form, email] = SECURITY_CONTACTS.map((contact) => contact.replace(/^mailto:/, ''));
    const policy = fs.readFileSync(path.join(ROOT, 'SECURITY.md'), 'utf8');
    expect(policy.indexOf(form)).toBeGreaterThan(-1);
    expect(policy.indexOf(email)).toBeGreaterThan(policy.indexOf(form));
    const contact = fs.readFileSync(path.join(ROOT, 'content', 'contact.md'), 'utf8');
    const section = contact.slice(contact.indexOf('## Security problems in sossscan'));
    expect(section.indexOf(form)).toBeGreaterThan(-1);
    expect(section.indexOf(email)).toBeGreaterThan(section.indexOf(form));
  });
});
