// Cloud and Payment Processor Integration Service

// VULNERABILITY: Hardcoded AWS Credentials
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

// VULNERABILITY: Hardcoded Stripe Live Secret Key
const STRIPE_SECRET_KEY = 'sk_live_51OzExampleFakeKeyForTestingPurposes12345';

// VULNERABILITY: Hardcoded GitHub Personal Access Token
const GITHUB_PAT = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';

function getCloudCredentials() {
  return {
    awsKey: AWS_ACCESS_KEY_ID,
    awsSecret: AWS_SECRET_ACCESS_KEY,
    stripeKey: STRIPE_SECRET_KEY,
    githubToken: GITHUB_PAT,
  };
}

module.exports = { getCloudCredentials };
