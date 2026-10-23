// Damn Vulnerable Node App (DVNA) Authentication Config
const JWT_SECRET = 'super_secret_jwt_signing_key_never_share_987654321';
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

function getAuthConfig() {
  return {
    jwtSecret: JWT_SECRET,
    awsKey: AWS_ACCESS_KEY_ID,
    awsSecret: AWS_SECRET_ACCESS_KEY,
  };
}

module.exports = { getAuthConfig };
