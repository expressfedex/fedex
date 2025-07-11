// secret_generator.js
const crypto = require('crypto');

// Generate a 32-byte (256-bit) random string
const jwtSecret = crypto.randomBytes(32).toString('hex');

console.log('Your JWT Secret:', jwtSecret);