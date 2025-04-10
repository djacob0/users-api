const mysql = require("mysql2/promise");
require("dotenv").config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  timezone: 'Z',
  connectionLimit: 10,
  queueLimit: 0
});

pool.getConnection()
  .then(() => console.log("Running"))
  .catch(err => {
    console.error("Database connection failed:", err);
    process.exit(1);
  });

module.exports = pool;
