/** User class for message.ly */

const { BCRYPT_WORK_FACTOR } = require("../config");
const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require('bcrypt');

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register({username, password, first_name, last_name, phone}) {
    let hashedPW = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const results = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
      RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPW, first_name, last_name, phone]
    );

    return results.rows[0]                               
  }

  /** Authenticate: is this username/password valid? Returns boolean. */
  static async authenticate(username, password) {
    const result = await db.query(`SELECT password FROM users WHERE username=$1`, [username]);
    if (!result.rows[0]) throw new ExpressError(`Username '${username}' cannot be found`, 404)
    return result.rows[0] && bcrypt.compare(password, result.rows[0].password)
  }

  /** Update last_login_at for user */
  static async updateLoginTimestamp(username) {
    const result = await db.query(`UPDATE users SET last_login_at = current_timestamp WHERE username=$1 RETURNING username`, [username]);
    if (!result.rows[0]) throw new ExpressError(`Username '${username}' cannot be found`, 404)
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */
  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone
      FROM users`
    );
    return results.rows
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */
  static async get(username) {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username=$1`,
      [username]
    );
    if (!result.rows[0]) throw new ExpressError(`Username '${username}' cannot be found`, 404)
    return result.rows[0]
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT m.id, m.to_username as to_user, m.body, m.sent_at, m.read_at
      FROM users AS u
      JOIN messages AS m
      ON u.username = m.from_username
      WHERE username=$1`,
      [username]
    );
    const userResult = await db.query(`SELECT username, first_name, last_name, phone FROM users WHERE username=$1`, [results.rows[0].to_user]);
    results.rows[0].to_user = userResult.rows[0]
    return results.rows
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */
  static async messagesTo(username) {
    const results = await db.query(
      `SELECT m.id, m.from_username as from_user, m.body, m.sent_at, m.read_at
      FROM users AS u
      JOIN messages AS m
      ON u.username = m.to_username
      WHERE username=$1`,
      [username] 
    );
    const userResult = await db.query(`SELECT username, first_name, last_name, phone FROM users WHERE username=$1`, [results.rows[0].from_user]);
    results.rows[0].from_user = userResult.rows[0]
    return results.rows
  }
}


module.exports = User;