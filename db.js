const mysql = require('mysql2/promise');
require('dotenv').config();

const dbConfig = {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT) || 10522,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.DB_SSL_MODE === 'REQUIRED' ? {
        rejectUnauthorized: false
    } : undefined,
    connectTimeout: 60000,
    acquireTimeout: 60000,
    timeout: 60000,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
    // Additional options to handle connection issues
    reconnect: true,
    insecureAuth: false,
    supportBigNumbers: true,
    bigNumberStrings: true,
    dateStrings: true,
    multipleStatements: false
};

const pool = mysql.createPool(dbConfig);

// Initialize database - create table if not exists
const initializeDatabase = async () => {
    let retries = 5;
    while (retries > 0) {
        try {
            const connection = await pool.getConnection();
            
            // Create users table according to the schema
            const createTableQuery = `
                CREATE TABLE IF NOT EXISTS users (
                    uid INT AUTO_INCREMENT PRIMARY KEY,
                    uname VARCHAR(100) NOT NULL,
                    email VARCHAR(100) NOT NULL UNIQUE,
                    phone VARCHAR(20) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    role ENUM('USER', 'ADMIN') DEFAULT 'USER',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `;
            
            await connection.execute(createTableQuery);
            console.log('Users table created or already exists');
            
            connection.release();
            break; // Exit the loop on success
        } catch (error) {
            retries--;
            console.error(`Database initialization error (attempt ${6-retries}/5):`, error.message);
            if (retries === 0) {
                console.error('Failed to connect to database after 5 attempts');
                throw error;
            }
            // Wait 2 seconds before retrying
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
};

module.exports = {
    pool,
    initializeDatabase
};
