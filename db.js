const mysql = require('mysql2/promise');
require('dotenv').config();

// Parse database URL if provided, otherwise use individual parameters
let dbConfig;
if (process.env.DB_HOST && process.env.DB_HOST.startsWith('mysql://')) {
    // Parse the connection string
    const dbUrl = new URL(process.env.DB_HOST);
    dbConfig = {
        host: dbUrl.hostname,
        port: parseInt(dbUrl.port) || 3306,
        user: dbUrl.username,
        password: dbUrl.password,
        database: dbUrl.pathname.substring(1), // Remove leading slash
        ssl: {
            rejectUnauthorized: false,
            // Force SSL for Aiven databases
            ca: process.env.MYSQL_SSL_CA || undefined,
            cert: process.env.MYSQL_SSL_CERT || undefined,
            key: process.env.MYSQL_SSL_KEY || undefined,
        },
        connectTimeout: 120000, // Increased timeout
        acquireTimeout: 120000, // Increased timeout
        timeout: 120000,        // Increased timeout
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
        multipleStatements: false,
        // Handle network-related issues
        charset: 'utf8mb4',
        compress: true,
        debug: false,
        trace: true,
        multipleStatements: false
    };
} else {
    // Use individual parameters
    dbConfig = {
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT) || 10522,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        ssl: process.env.DB_SSL_MODE === 'REQUIRED' ? {
            rejectUnauthorized: false,
            ca: process.env.MYSQL_SSL_CA || undefined,
            cert: process.env.MYSQL_SSL_CERT || undefined,
            key: process.env.MYSQL_SSL_KEY || undefined,
        } : undefined,
        connectTimeout: 120000, // Increased timeout
        acquireTimeout: 120000, // Increased timeout
        timeout: 120000,        // Increased timeout
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
        multipleStatements: false,
        // Handle network-related issues
        charset: 'utf8mb4',
        compress: true,
        debug: false,
        trace: true,
        multipleStatements: false
    };
}

const pool = mysql.createPool(dbConfig);

// In-memory fallback for users when database is unavailable
let memoryUsers = [];
let useDatabase = true;

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
            useDatabase = true;
            break; // Exit the loop on success
        } catch (error) {
            retries--;
            console.error(`Database initialization error (attempt ${6-retries}/5):`, error.message);
            if (retries === 0) {
                console.warn('Database connection failed after 5 attempts. Falling back to in-memory storage.');
                useDatabase = false;
                // Reset retries to continue without database
                break;
            }
            // Wait 2 seconds before retrying
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
};

// Helper functions to handle database operations with fallback
const createUser = async (name, email, phone, hashedPassword) => {
    if (useDatabase) {
        try {
            await pool.execute(
                'INSERT INTO users (uname, email, phone, password, role) VALUES (?, ?, ?, ?, ?)',
                [name.trim(), email.toLowerCase().trim(), phone.trim(), hashedPassword, 'USER']
            );
            return { success: true };
        } catch (error) {
            console.error('Database insert error:', error.message);
            // Fallback to in-memory storage
            memoryUsers.push({
                uid: Date.now(),
                uname: name.trim(),
                email: email.toLowerCase().trim(),
                phone: phone.trim(),
                password: hashedPassword,
                role: 'USER',
                created_at: new Date()
            });
            return { success: true };
        }
    } else {
        // Use in-memory storage
        memoryUsers.push({
            uid: Date.now(),
            uname: name.trim(),
            email: email.toLowerCase().trim(),
            phone: phone.trim(),
            password: hashedPassword,
            role: 'USER',
            created_at: new Date()
        });
        return { success: true };
    }
};

const findUserByEmail = async (email) => {
    if (useDatabase) {
        try {
            const [users] = await pool.execute(
                'SELECT * FROM users WHERE email = ?',
                [email.toLowerCase().trim()]
            );
            return users.length > 0 ? users[0] : null;
        } catch (error) {
            console.error('Database query error:', error.message);
            // Fallback to in-memory storage
            return memoryUsers.find(user => user.email === email.toLowerCase().trim()) || null;
        }
    } else {
        // Use in-memory storage
        return memoryUsers.find(user => user.email === email.toLowerCase().trim()) || null;
    }
};

const checkUserExists = async (email) => {
    if (useDatabase) {
        try {
            const [users] = await pool.execute(
                'SELECT * FROM users WHERE email = ?',
                [email.toLowerCase().trim()]
            );
            return users.length > 0;
        } catch (error) {
            console.error('Database query error:', error.message);
            // Fallback to in-memory storage
            return memoryUsers.some(user => user.email === email.toLowerCase().trim());
        }
    } else {
        // Use in-memory storage
        return memoryUsers.some(user => user.email === email.toLowerCase().trim());
    }
};

// Export the database functions with fallback
module.exports = {
    pool,
    initializeDatabase,
    createUser,
    findUserByEmail,
    checkUserExists,
    get useDatabase() {
        return useDatabase;
    }
};
