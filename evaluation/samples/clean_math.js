// Clean Math Utility - No security vulnerabilities
function add(a, b) {
  if (typeof a !== 'number' || typeof b !== 'number') {
    throw new TypeError('Operands must be numbers');
  }
  return a + b;
}

function calculateTax(subtotal, rate = 0.08) {
  if (subtotal < 0 || rate < 0) {
    throw new Error('Amounts must be non-negative');
  }
  return Number((subtotal * rate).toFixed(2));
}

function formatCurrency(amount) {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
  }).format(amount);
}

module.exports = { add, calculateTax, formatCurrency };
