
const mysql = require('mysql2');
const { database } = require('./config');

// Create a connection pool
const pool = mysql.createPool({
  ...database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Export a promise-wrapped version of the pool
module.exports = pool.promise();
