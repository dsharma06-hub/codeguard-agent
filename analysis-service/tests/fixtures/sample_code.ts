/**
 * CodeGuard Test Fixture: Mixed safe code and hardcoded secrets.
 * Used to verify detector precision, recall, and false positive avoidance.
 */

// ==========================================
// 1. SAFE CODE CONSTRUCTS (MUST NOT TRIGGER)
// ==========================================

export const API_URL = "https://api.example.com/v1";
export const API_ENDPOINT = "/api/v1/auth/callback";
export const TOKEN_TYPE = "Bearer";
export const KEY_NAME = "production_cluster_key";
export const DUMMY_API_KEY = "YOUR_API_KEY_HERE";
export const AUTH_HEADER = "Authorization";
export const WEBHOOK_SECRET_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
export const SAFE_ENV_SECRET = process.env.DATABASE_PASSWORD || "";

export function getHeaders() {
  return {
    "Content-Type": "application/json",
    "Accept": "application/json",
  };
}

// ==========================================
// 2. HARDCODED SECRETS (MUST TRIGGER)
// ==========================================

// Line 31: Plaintext AWS Access Key ID
export const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";

// Line 34: Plaintext Stripe Secret Key
export const STRIPE_SECRET_KEY = "sk_live_51MzT99ABcdeFGhijkLMNoPQRstuv1234";

// Line 37: Plaintext GitHub Personal Access Token
export const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";

// Line 40: Hardcoded JSON Web Token
export const JWT_AUTH = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0.g4z5h6j7k8l9m0n1o2p3q4r5s6t7u8v9w0x1y2z";

// Line 43: High-entropy secret assigned to suspicious identifier
export const CLIENT_SECRET = "9f8b2c4e1a7d6e3f5b0c9a8d7e6f5a4b";

// Line 48: Embedded secret inside object property
export const paymentConfig = {
  provider: "stripe",
  apiKey: "sk_test_51MzT99ABcdeFGhijkLMNoPQRstuv1234",
  webhookUrl: "https://api.example.com/stripe/webhook",
};
