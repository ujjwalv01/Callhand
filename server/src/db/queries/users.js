// Data access for the `users` table.
//
// Every SQL statement in the app lives in a src/db/queries/* module. Routes
// call these functions and never write SQL themselves, so:
//   * there is one place to audit every query that touches a table
//   * the shape returned to routes is controlled here (password_hash never
//     escapes by accident)
//   * swapping a query for a view or a join changes one file

import { query } from '../client.js';

// Columns safe to return to a caller. `password_hash` is deliberately absent:
// a SELECT * would leak it into API responses the moment someone forgets to
// strip it. Whitelisting is the safer default.
const PUBLIC_COLUMNS = 'id, email, full_name, created_at';

/**
 * Insert a new user.
 * A duplicate email raises Postgres 23505, which errorMiddleware turns into a
 * 409 - so there is no need (and no safe way) to pre-check for existence.
 */
export async function createUser({ email, passwordHash, fullName = null }) {
  const { rows } = await query(
    `INSERT INTO users (email, password_hash, full_name)
     VALUES ($1, $2, $3)
     RETURNING ${PUBLIC_COLUMNS}`,
    [email, passwordHash, fullName],
  );
  return rows[0];
}

/**
 * Look up a user for login. This is the ONE function that returns the hash,
 * hence the explicit name - a reviewer can grep for `WithHash` to find every
 * place credentials are handled.
 */
export async function findUserByEmailWithHash(email) {
  const { rows } = await query(
    `SELECT ${PUBLIC_COLUMNS}, password_hash FROM users WHERE email = $1`,
    [email],
  );
  return rows[0] ?? null;
}

/** Load the user behind a verified token, for req.user. */
export async function findUserById(id) {
  const { rows } = await query(`SELECT ${PUBLIC_COLUMNS} FROM users WHERE id = $1`, [id]);
  return rows[0] ?? null;
}

/** Used by the signup flow's "is this email free?" check in the UI, not for auth. */
export async function emailExists(email) {
  const { rows } = await query('SELECT 1 FROM users WHERE email = $1', [email]);
  return rows.length > 0;
}
