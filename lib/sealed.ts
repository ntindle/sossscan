/**
 * Sealed values: data the browser carries but can't read or change. Sign-in cookies, the GitHub sign-in handshake and
 * pull request previews all use them, so the server keeps nothing between requests.
 *
 * A sealed value is AES-256-GCM over the JSON (compressed), with its creation time authenticated alongside it. Each
 * purpose has its own key (HMAC of the master key), so a preview can't pass as a sign-in cookie or the other way round.
 * The master key is SOSF_SECRET, on every host. The server never makes up or saves a key of its own, so without
 * SOSF_SECRET nothing is sealed and sign-in is off; public scans don't need it.
 */
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { HttpError } from './http.ts';

const FORMAT = 1;
const HEAD = 9; // format byte + creation time (8 bytes, seconds)
const IV = 12;
const TAG = 16;
const MAX_CLOCK_SKEW = 60;
/** `openssl rand -hex 32` gives 64 characters; anything under 32 is too easy to guess. */
const MIN_SECRET_LENGTH = 32;

/** The key behind sign-in cookies, handshakes and sealed previews. */
function masterKey(): Buffer {
  const secret = process.env.SOSF_SECRET || '';
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new HttpError(
      503,
      'server_misconfigured',
      "This site isn't fully set up: SOSF_SECRET is missing or too short.",
      "Public scans still work. The site's operator can set SOSF_SECRET to turn on sign-in.",
    );
  }
  return crypto.createHash('sha256').update(secret).digest();
}

function keyFor(purpose: string): Buffer {
  return crypto.createHmac('sha256', masterKey()).update(purpose).digest();
}

/** Encrypt and sign data for the browser to carry. Only this server can read or change it. */
export function seal(purpose: string, data: object): string {
  const key = keyFor(purpose);
  const head = Buffer.alloc(HEAD);
  head.writeUInt8(FORMAT, 0);
  head.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000)), 1);
  const iv = crypto.randomBytes(IV);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(head);
  const body = Buffer.concat([cipher.update(zlib.deflateSync(Buffer.from(JSON.stringify(data)))), cipher.final()]);
  return Buffer.concat([head, iv, body, cipher.getAuthTag()]).toString('base64url');
}

/** The data from seal(), or null when it's missing, altered, from another purpose or older than ttl seconds. */
export function unseal<T extends object = Record<string, any>>(
  purpose: string,
  token: string | null | undefined,
  ttl: number,
): T | null {
  if (!token) return null;
  const key = keyFor(purpose); // outside the try: a site with no secret must say so, not act as if signed out
  const raw = Buffer.from(token, 'base64url');
  if (raw.length < HEAD + IV + TAG || raw[0] !== FORMAT) return null;
  const head = raw.subarray(0, HEAD);
  const made = Number(head.readBigUInt64BE(1));
  const now = Math.floor(Date.now() / 1000);
  if (made + ttl < now || made > now + MAX_CLOCK_SKEW) return null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, raw.subarray(HEAD, HEAD + IV));
    decipher.setAAD(head);
    decipher.setAuthTag(raw.subarray(raw.length - TAG));
    const plain = Buffer.concat([decipher.update(raw.subarray(HEAD + IV, raw.length - TAG)), decipher.final()]);
    const data: unknown = JSON.parse(zlib.inflateSync(plain).toString('utf8'));
    return data && typeof data === 'object' && !Array.isArray(data) ? (data as T) : null;
  } catch {
    return null;
  }
}
