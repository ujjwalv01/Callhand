// Password hashing and JWT issuing. Pure functions - no database, no Express.
//
// Keeping this layer free of I/O means the security-critical logic can be
// reasoned about and tested on its own, and the routes stay readable.

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { unauthorized, badRequest } from '../lib/errors.js';

// Work factor. Each +1 doubles the time to hash. 12 is ~250ms on modern
// hardware: slow enough that offline brute-forcing a stolen hash is
// impractical, fast enough that a login does not feel sluggish.
// Revisit as hardware improves - it is a moving target, not a constant.
const BCRYPT_ROUNDS = 12;

// bcrypt silently TRUNCATES input beyond 72 bytes: "long password" and
// "long password + more" would hash identically. We reject instead of
// truncating, so nobody ends up with a weaker password than they think.
const MAX_PASSWORD_BYTES = 72;

/** @param {string} plain @returns {Promise<string>} the bcrypt hash (includes its own salt) */
export async function hashPassword(plain) {
  if (Buffer.byteLength(plain, 'utf8') > MAX_PASSWORD_BYTES) {
    throw badRequest(`Password must be at most ${MAX_PASSWORD_BYTES} bytes`, { code: 'password_too_long' });
  }
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

/**
 * Compare a candidate password against a stored hash.
 * bcrypt.compare re-derives the hash using the salt embedded in `hash` and
 * compares in constant time, so it leaks no information through timing.
 */
export async function verifyPassword(plain, hash) {
  if (!hash) return false;
  return bcrypt.compare(plain, hash);
}

// A precomputed hash of a random string. Used to burn the same ~250ms when
// an email does not exist as when it does - see routes/auth.js. Without it,
// "unknown email" returns in 5ms and "wrong password" in 250ms, which lets an
// attacker enumerate which emails have accounts purely by timing responses.
const DUMMY_HASH = bcrypt.hashSync('unused-placeholder-for-timing-equalisation', BCRYPT_ROUNDS);
export const burnTimingBudget = () => bcrypt.compare('x', DUMMY_HASH);

/**
 * Issue a signed JWT.
 * The payload is base64-encoded, NOT encrypted - anyone holding the token can
 * read it. Put identifiers in it, never secrets.
 */
export function signToken(user) {
  return jwt.sign(
    { email: user.email },              // public claims
    config.jwt.secret,
    {
      subject: user.id,                 // `sub` - who the token is about
      expiresIn: config.jwt.expiresIn,  // `exp` - hard expiry, checked on verify
      issuer: 'callhand',               // `iss` - rejects tokens minted by another service
      algorithm: 'HS256',
    },
  );
}

/**
 * Verify and decode a token. Throws 401 for anything suspect.
 *
 * `algorithms: ['HS256']` is a security requirement, not a default: without
 * pinning it, a forged token with `"alg": "none"` (or an algorithm-confusion
 * attack swapping HMAC for RSA) could be accepted as valid.
 */
export function verifyToken(token) {
  try {
    const payload = jwt.verify(token, config.jwt.secret, {
      algorithms: ['HS256'],
      issuer: 'callhand',
    });
    return { id: payload.sub, email: payload.email };
  } catch (err) {
    const message = err.name === 'TokenExpiredError' ? 'Session expired' : 'Invalid token';
    throw unauthorized(message, { code: err.name === 'TokenExpiredError' ? 'token_expired' : 'invalid_token', cause: err });
  }
}

/** Pull a bearer token out of the Authorization header. */
export function extractBearerToken(headerValue) {
  if (!headerValue) return null;
  const [scheme, token] = headerValue.split(' ');
  return scheme?.toLowerCase() === 'bearer' && token ? token : null;
}
