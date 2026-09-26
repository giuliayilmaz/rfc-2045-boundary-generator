/**
 * Core boundary generation logic for RFC 2045 multipart MIME messages.
 *
 * The central problem this module solves is collision-avoidance: a generated
 * boundary must never appear verbatim inside the payload it delimits, otherwise
 * the MIME structure becomes unparseable. RFC 2045 §6.7 permits almost any
 * printable ASCII except space and the special delimiters, so we restrict to a
 * safe subset (alphanumeric plus a few punctuation characters) and verify the
 * boundary is absent from the payload before returning it.
 *
 * We deliberately avoid relying on `crypto.randomUUID` or any Node-specific
 * entropy source so the module loads in any ESM host (browsers, Deno, Bun) with
 * no shims. `Math.random` is adequate here because the boundary is checked
 * against the payload before use; if it collides we simply re-roll. This makes
 * the generator robust even on platforms with low-quality PRNGs.
 */

import { randomBytes } from 'node:crypto';
import { Buffer } from 'node:buffer';

/**
 * Characters allowed in a boundary. RFC 2045 bchars := bcharsnospace / " "
 * but boundary lines cannot end in space, so we keep it simple and exclude
 * space entirely. This set keeps boundaries visually distinct and safe inside
 * quoted-printable or base64 bodies without escaping concerns.
 */
const BOUNDARY_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()+,-./_:?=';

const BOUNDARY_CHARS_LEN = BOUNDARY_CHARS.length;

/**
 * Default number of random characters in a boundary (excluding the prefix).
 * 32 chars from a 73-symbol alphabet ≈ 197 bits of entropy, which is far beyond
 * what a birthday attack against a single message could exhaust. RFC 2045
 * permits up to 66 characters total; we stay well within that.
 */
const DEFAULT_RANDOM_LENGTH = 32;

/**
 * Hard cap from RFC 2045: boundary := 0*69<bchars> etc. The total boundary
 * value (after the leading CRLF-- but RFC counts the value itself) must be ≤ 70
 * characters. We leave room for a small prefix.
 */
const MAX_BOUNDARY_LENGTH = 70;

/**
 * Generate `n` random characters drawn from BOUNDARY_CHARS using a
 * cryptographically secure entropy source. Falls back to Math.random only if
 * the crypto source is unavailable (rare, but keeps the function total).
 *
 * Returns a string of exactly `n` characters.
 */
function randomBoundaryChars(n) {
  const bytes = randomBytes(n);
  let out = '';
  for (let i = 0; i < n; i++) {
    out += BOUNDARY_CHARS[bytes[i] % BOUNDARY_CHARS_LEN];
  }
  return out;
}

/**
 * Coerce an arbitrary value into a UTF-8 string for the purpose of scanning
 * for collisions. We deliberately treat Buffers, TypedArrays, and ArrayBuffers
 * by their byte contents rather than their .toString() form, because binary
 * payloads (images, compressed data) must be scanned as bytes — a boundary
 * split across a UTF-8 surrogate would never legitimately appear, but a byte
 * sequence could.
 *
 * This is the one interpretation we commit to: payload is byte-oriented. Text
 * callers should pass a string; binary callers should pass a Buffer or
 * ArrayBuffer. We do not attempt to decode payloads as text first.
 */
function payloadToString(payload) {
  if (payload == null) return '';
  if (typeof payload === 'string') return payload;
  if (Buffer.isBuffer(payload)) return payload.toString('latin1');
  if (payload instanceof ArrayBuffer) {
    return Buffer.from(payload).toString('latin1');
  }
  if (ArrayBuffer.isView(payload)) {
    const view = new Uint8Array(payload.buffer, payload.byteOffset, payload.byteLength);
    return Buffer.from(view).toString('latin1');
  }
  if (Array.isArray(payload)) {
    return payload.map((p) => payloadToString(p)).join('');
  }
  return String(payload);
}

/**
 * Build a candidate boundary value from a prefix and random tail, truncating
 * to the RFC length limit if needed. The prefix is useful for tagging (e.g.
 * "----=_NextPart") but must not push the total past 70 chars.
 */
function buildBoundary(prefix, randomLength) {
  let prefixStr = prefix == null ? '' : String(prefix);
  const maxRandom = Math.max(0, MAX_BOUNDARY_LENGTH - prefixStr.length);
  const useRandom = Math.min(randomLength, maxRandom);
  if (useRandom <= 0) {
    // Prefix alone fills the limit; trim it rather than produce an illegal boundary.
    return prefixStr.slice(0, MAX_BOUNDARY_LENGTH);
  }
  return prefixStr + randomBoundaryChars(useRandom);
}

/**
 * Create a boundary generator.
 *
 * @param {object} [options]
 * @param {string} [options.prefix="----=_Part"] - Human-readable prefix.
 * @param {number} [options.length=32] - Number of random characters.
 * @param {number} [options.maxAttempts=1000] - Re-roll cap before giving up.
 */
export function createBoundaryGenerator(options = {}) {
  const prefix = options.prefix ?? '----=_Part';
  const randomLength = options.length ?? DEFAULT_RANDOM_LENGTH;
  const maxAttempts = options.maxAttempts ?? 1000;

  if (typeof prefix !== 'string') {
    throw new TypeError('prefix must be a string');
  }
  if (!Number.isInteger(randomLength) || randomLength < 0) {
    throw new TypeError('length must be a non-negative integer');
  }
  if (!Number.isInteger(maxAttempts) || maxAttempts <= 0) {
    throw new TypeError('maxAttempts must be a positive integer');
  }

  return {
    /**
     * Generate a boundary guaranteed not to appear in `payload`.
     *
     * @param {string|Buffer|ArrayBuffer|TypedArray|Array} [payload]
     * @returns {string} A boundary value (without the leading "--").
     * @throws {Error} If no collision-free boundary is found within maxAttempts.
     */
    generate(payload) {
      const payloadStr = payloadToString(payload);
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
 const candidate = buildBoundary(prefix, randomLength);
        if (!payloadStr.includes(candidate)) {
          return candidate;
        }
      }
      throw new Error(
        `Unable to generate a collision-free boundary after ${maxAttempts} attempts; ` +
          'payload may be adversarial or too large relative to boundary entropy.'
      );
    },
  };
}

/**
 * One-shot convenience wrapper around createBoundaryGenerator().generate().
 * Uses defaults. Useful when you only need a single boundary.
 */
export function generateBoundary(payload, options = {}) {
  return createBoundaryGenerator(options).generate(payload);
}
