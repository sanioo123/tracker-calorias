// lib/db.js
import mysql from 'mysql2/promise';

const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '', // Tu contraseña de MySQL
  database: 'calorie_tracker',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
};

let pool;

export async function getConnection() {
  if (!pool) {
    pool = mysql.createPool(dbConfig);
  }
  return pool;
}

export async function query(sql, params = []) {
  const connection = await getConnection();
  try {
    const [results] = await connection.execute(sql, params);
    return results;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  }
}

