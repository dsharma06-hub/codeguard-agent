"""Python test fixture containing real hardcoded secrets across multiple AST shapes.

Used to verify true positive detection for:
- Simple assignment
- Keyword arguments
- Dictionary entries
- Class attributes and module-level constants
- Django-style settings
- High-confidence signatures (AWS, GitHub, Stripe, Private Keys, JWT)
- Compound high-entropy secrets (client_secret, db_password, webhook_signing_key)
- f-strings and format calls
"""

# 1. Simple assignment with AWS Access Key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# 2. Module-level GitHub PAT
GITHUB_PAT = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"

# 3. High-entropy compound identifiers
client_secret = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
db_password = "SuperSecretPassword123!"
webhook_signing_key = "whsec_abcdef1234567890abcdef123456"

# 4. Class attributes and Django-style settings
class ProductionSettings:
    SECRET_KEY = "django-insecure-8f9e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
    STRIPE_KEY = "sk_live_1234567890abcdefghijklmn12"

# 5. Function call with keyword argument
def configure_client():
    connect_database(password="SuperSecretPassword123!")

def connect_database(password=None):
    pass

# 6. Dictionary entries
API_CONFIG = {
    "api_key": "sk_live_1234567890abcdefghijklmn12",
}

# 7. Private Key PEM block
RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y9X7M4eKqP...
-----END RSA PRIVATE KEY-----"""

# 8. JWT Token
AUTH_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# 9. Secret in f-string
AUTH_HEADER_FSTRING = f"Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"

# 10. Secret in format call
AUTH_HEADER_FORMAT = "Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyzAB".format()
