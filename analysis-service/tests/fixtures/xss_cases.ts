/**
 * CodeGuard Cross-Site Scripting (XSS) Test Fixture
 * Contains labeled test cases for true positives, false positives, sanitizers, and edge cases.
 */

import express from 'express';
import DOMPurify from 'dompurify';
import escapeHtml from 'escape-html';

const app = express();

// ============================================================================
// CASE 1: [TRUE POSITIVE - CRITICAL] Direct assignment to element.innerHTML
// User input from `req.query.content` is assigned directly to innerHTML.
// ============================================================================
export function case1_domInnerHtmlDirect(req: express.Request, element: HTMLElement) {
  element.innerHTML = req.query.content as string;
}

// ============================================================================
// CASE 2: [TRUE POSITIVE - CRITICAL] Reassigned tainted variable reaching outerHTML
// Untrusted route parameter `req.params.id` is reassigned across variables.
// ============================================================================
export function case2_multiHopReassignedTaint(req: express.Request, element: HTMLElement) {
  const rawId = req.params.id;
  const temp = rawId;
  const markup = "<div id='" + temp + "'>Item</div>";
  element.outerHTML = markup;
}

// ============================================================================
// CASE 3: [TRUE POSITIVE - CRITICAL] Client-side DOM XSS via window.location & URLSearchParams
// Untrusted query parameter extracted via URLSearchParams injected into DOM.
// ============================================================================
export function case3_browserLocationSearchParams(element: HTMLElement) {
  const params = new URLSearchParams(window.location.search);
  const q = params.get('q');
  element.innerHTML = "Search results for: " + q;
}

// ============================================================================
// CASE 4: [TRUE POSITIVE - CRITICAL] React dangerouslySetInnerHTML with unsanitized input
// Unsanitized request payload passed into React's dangerouslySetInnerHTML attribute.
// ============================================================================
export function case4_reactDangerouslySetInnerHTML(req: express.Request) {
  const userMarkup = req.body.markup;
  return (
    <div className="user-bio" dangerouslySetInnerHTML={{ __html: userMarkup }} />
  );
}

// ============================================================================
// CASE 5: [TRUE POSITIVE - CRITICAL] Server-side reflected XSS in res.send()
// Unescaped user query parameter concatenated into HTML response body.
// ============================================================================
export function case5_reflectedXssResSend(req: express.Request, res: express.Response) {
  const username = req.query.name;
  res.send("<h1>Welcome back, " + username + "!</h1>");
}

// ============================================================================
// CASE 6: [TRUE POSITIVE - CRITICAL] document.write and insertAdjacentHTML with tainted input
// Untrusted inputs fed into document.write and element.insertAdjacentHTML.
// ============================================================================
export function case6_documentWriteAndAdjacentHtml(req: express.Request, element: HTMLElement) {
  document.write("<script src='" + req.query.scriptUrl + "'></script>");
  element.insertAdjacentHTML('beforeend', `<div>${req.body.snippet}</div>`);
}

// ============================================================================
// CASE 7: [TRUE POSITIVE - CRITICAL] Code injection via eval() and Function constructor
// User input executed dynamically as code.
// ============================================================================
export function case7_evalCodeInjection(req: express.Request) {
  const formula = req.query.calc as string;
  eval(formula);
  const dynamicFn = new Function("a", req.body.code);
}

// ============================================================================
// CASE 8: [TRICKY CASE - MEDIUM] Sanitizer detected: DOMPurify.sanitize()
// Input passes through DOMPurify before innerHTML; flagged as MEDIUM for audit.
// ============================================================================
export function case8_domPurifySanitizer(req: express.Request, element: HTMLElement) {
  const clean = DOMPurify.sanitize(req.body.bio);
  element.innerHTML = clean;
}

// ============================================================================
// CASE 9: [TRICKY CASE - MEDIUM] Sanitizer detected: escapeHtml()
// Input passes through escapeHtml() before res.send(); flagged as MEDIUM.
// ============================================================================
export function case9_escapeHtmlSanitizer(req: express.Request, res: express.Response) {
  const safeName = escapeHtml(req.query.name as string);
  res.send("<p>Hello " + safeName + "</p>");
}

// ============================================================================
// CASE 10: [FALSE POSITIVE - SAFE] React default JSX text rendering (auto-escaped)
// React automatically escapes string values within JSX text curly braces.
// ============================================================================
export function case10_reactDefaultJsxAutoEscaping(req: express.Request) {
  const userName = req.query.name;
  return (
    <div className="profile">
      <h1>Hello {userName}</h1>
      <p>{req.body.description}</p>
    </div>
  );
}

// ============================================================================
// CASE 11: [FALSE POSITIVE - SAFE] Hardcoded static HTML string
// Static constant strings assigned to innerHTML or res.send contain no taint.
// ============================================================================
export function case11_hardcodedStaticInnerHtml(element: HTMLElement, res: express.Response) {
  element.innerHTML = "<span class='badge'>Static Verified Content</span>";
  res.send("<h1>Static Safe Dashboard</h1>");
}

// ============================================================================
// CASE 12: [FALSE POSITIVE - SAFE] Safe JSON response (res.json)
// res.json sets application/json Content-Type, safe from HTML rendering.
// ============================================================================
export function case12_safeJsonResponse(req: express.Request, res: express.Response) {
  return res.json({
    status: "ok",
    query: req.query.filter,
    total: 42
  });
}
