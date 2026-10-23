/**
 * CodeGuard SQL Injection Test Fixture
 * Contains labeled test cases for true positives, false positives, sanitizers, and edge cases.
 */

import express from 'express';
import { db, connection, pool } from './database';
import { User, Product } from './models';
import { escape } from 'sqlstring';

const app = express();

// ============================================================================
// CASE 1: [TRUE POSITIVE - CRITICAL] Direct template literal in raw query call
// Interpolates tainted `req.query.name` directly into db.query call without placeholders.
// ============================================================================
export async function case1_directTemplateLiteral(req: express.Request, res: express.Response) {
  const result = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  return res.json(result);
}

// ============================================================================
// CASE 2: [TRUE POSITIVE - CRITICAL] String concatenation (+) with tainted input
// Assembles query string using binary addition (+) with `req.query.category`.
// ============================================================================
export async function case2_stringConcatenation(req: express.Request, res: express.Response) {
  const query = "SELECT * FROM products WHERE category = '" + req.query.category + "'";
  const products = await connection.execute(query);
  return res.json(products);
}

// ============================================================================
// CASE 3: [TRUE POSITIVE - CRITICAL] Reassigned tainted variable
// Tainted input `req.params.id` is reassigned to `filter` before reaching query.
// ============================================================================
export async function case3_reassignedTaintedVariable(req: express.Request, res: express.Response) {
  const orderId = req.params.id;
  const filter = orderId;
  const sql = `SELECT * FROM orders WHERE id = '${filter}'`;
  const orders = await pool.query(sql);
  return res.json(orders);
}

// ============================================================================
// CASE 4: [TRUE POSITIVE - CRITICAL] Function parameter directly interpolated
// Parameter `userId` is interpolated directly into raw query string.
// ============================================================================
export async function case4_functionParamDirectInterpolation(userId: string) {
  return await db.query(`SELECT * FROM accounts WHERE user_id = ${userId}`);
}

// ============================================================================
// CASE 5: [TRICKY CASE - MEDIUM] Sanitizer function detected (escape / mysql.escape)
// Tainted input passes through `escape()`. Flagged as MEDIUM severity for manual review.
// ============================================================================
export async function case5_sanitizerDetected(req: express.Request, res: express.Response) {
  const safeTitle = escape(req.query.title);
  const sql = `SELECT * FROM articles WHERE title = '${safeTitle}'`;
  const articles = await db.query(sql);
  return res.json(articles);
}

// ============================================================================
// CASE 6: [FALSE POSITIVE - SAFE] Parameterized query with bind variables ($1, ?)
// Query string is a static template; user input is passed safely in parameter array.
// ============================================================================
export async function case6_parameterizedQuery(req: express.Request, res: express.Response) {
  const userId = req.query.id;
  const role = req.body.role;
  const result = await db.query(
    "SELECT * FROM users WHERE id = $1 AND role = ?",
    [userId, role]
  );
  return res.json(result);
}

// ============================================================================
// CASE 7: [FALSE POSITIVE - SAFE] String concatenation with safe constants
// Query is assembled using hardcoded strings and enum constants, with no user input.
// ============================================================================
const DEFAULT_LIMIT = 50;
const BASE_QUERY = "SELECT * FROM audit_logs WHERE status = 'FAILED'";
export async function case7_safeConstantConcatenation(res: express.Response) {
  const fullQuery = BASE_QUERY + " ORDER BY timestamp DESC LIMIT " + DEFAULT_LIMIT;
  const logs = await db.query(fullQuery);
  return res.json(logs);
}

// ============================================================================
// CASE 8: [FALSE POSITIVE - SAFE] ORM method with bound object argument
// Sequelize / Prisma query methods parameterize automatically under the hood.
// ============================================================================
export async function case8_ormMethodCall(req: express.Request, res: express.Response) {
  const user = await User.findOne({
    where: {
      email: req.query.email,
      status: "active"
    }
  });
  return res.json(user);
}

// ============================================================================
// CASE 9: [FALSE POSITIVE - SAFE] Parameterized query inside helper function
// Function parameter passed into prepared statement bind array.
// ============================================================================
export async function case9_safeFunctionParam(userId: string) {
  return await db.query("SELECT * FROM profiles WHERE user_id = $1", [userId]);
}
