# RFC 2045 Boundary Generator

Generates MIME multipart boundary strings and verifies they do not collide with the enclosed payload before returning them.

```js
import { createBoundaryGenerator, generateBoundary } from './src/index.js';

const gen = createBoundaryGenerator({ prefix: '----=_Part', length: 32 });
const boundary = gen.generate(Buffer.from('email body'));

// or one-shot:
const b = generateBoundary('plain text body');
```

## Why this exists

MIME multipart parsers split on `--<boundary>` lines. If that exact character sequence appears inside any body part, the message becomes ambiguous. RFC 2045 permits almost any printable ASCII in a boundary, which gives implementations freedom but no safety net: you still have to confirm the chosen string does not occur in the payload.

This library does that confirmation. It draws from `node:crypto.randomBytes`, scans the payload as bytes (latin1) for the candidate, and re-rolls on collision up to a configurable attempt cap.

## Edge you will hit

**Byte-oriented scanning.** Payloads are treated as byte sequences, not decoded text. A `Buffer` or `TypedArray` is scanned via its raw bytes; a string is scanned as its character sequence. This matters for binary bodies: a boundary that would be a valid byte substring of an image is correctly rejected, even though it might not be valid UTF-8. Do not pre-encode binary payloads to base64 before passing them in — that defeats the check.

**Adversarial payloads.** If you request a very short random length (e.g. 2 characters) against a payload containing every possible 2-character combination, the generator will exhaust its attempt budget and throw. Raise `length` (default 32, ≈197 bits of entropy) for any real use.

**Length cap.** RFC 2045 limits boundary values to 70 characters. If your prefix plus requested length exceeds that, the result is truncated to 70 characters. A prefix longer than 70 is truncated on its own.
