/**
 * The site's security.txt (RFC 9116, https://www.rfc-editor.org/rfc/rfc9116), served at /.well-known/security.txt by
 * app/.well-known/security.txt/route.ts: where to report a security problem in the site, the scanner, the CLI or the
 * GitHub Apps. Its contacts are the ones SECURITY.md and the contact page give, in the same order (a test checks):
 * GitHub's private reporting form first, then email for anyone who can't use it.
 */
import { REPO_URL, SITE } from './pages.ts';

export const SECURITY_TXT_PATH = '/.well-known/security.txt';

export const SECURITY_CONTACTS = [`${REPO_URL}/security/advisories/new`, 'mailto:sossscan@ntindle.com'] as const;

/** RFC 9116 recommends an Expires under a year away, so a file nobody renews says its details may be out of date. */
const VALID_DAYS = 360;

/** security.txt for a site built at `built`. It expires at midnight UTC, 360 days on. */
export function securityTxt(built: Date): string {
  const expires = new Date(built.getTime() + VALID_DAYS * 86_400_000);
  expires.setUTCHours(0, 0, 0, 0);
  return [
    '# How to report a security problem in sossscan: the site, its API, the CLI or the GitHub Apps.',
    ...SECURITY_CONTACTS.map((contact) => `Contact: ${contact}`),
    `Expires: ${expires.toISOString().replace('.000Z', 'Z')}`,
    `Policy: ${REPO_URL}/blob/main/SECURITY.md`,
    'Preferred-Languages: en',
    `Canonical: ${SITE}${SECURITY_TXT_PATH}`,
    '',
  ].join('\n');
}
