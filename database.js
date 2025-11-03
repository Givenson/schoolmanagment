
const mysql = require('mysql2');

// Create a connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'school_management',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Export a promise-wrapped version of the pool
module.exports = pool.promise();
