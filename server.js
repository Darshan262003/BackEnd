const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const { pool, initializeDatabase } = require('./db');

// In-memory fallback for when database is not available
const memoryUsers = [];
let useDatabase = true;

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cookieParser());

// CORS configuration - allow only deployed frontend
const allowedOrigins = [
    process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

// Validation helper
const validateRegistration = (data) => {
    const { name, email, phoneNumber, password } = data;
    const errors = [];

    if (!name || typeof name !== 'string' || name.trim().length < 2) {
        errors.push('Name is required and must be at least 2 characters');
    }

    if (!email || typeof email !== 'string') {
        errors.push('Email is required');
    } else {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            errors.push('Invalid email format');
        }
    }

    if (!phoneNumber || typeof phoneNumber !== 'string') {
        errors.push('Phone number is required');
    } else {
        const phoneRegex = /^[\d\s\-\+\(\)]{10,15}$/;
        if (!phoneRegex.test(phoneNumber)) {
            errors.push('Invalid phone number format');
        }
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
        errors.push('Password is required and must be at least 6 characters');
    }

    return errors;
};

// Enhanced database initialization with retry mechanism for server routes
const ensureDbInitializedWithRetry = async () => {
    let retries = 3;
    while (retries > 0) {
        try {
            // We're assuming the database should already be initialized by startServer
            // But if needed, we can call initializeDatabase again
            break; // For server.js, we expect it to be initialized already
        } catch (error) {
            retries--;
            console.error(`Database initialization in server route failed (attempt ${4-retries}/3):`, error.message);
            if (retries === 0) {
                console.error('Server route failed to connect to database after 3 attempts');
                throw error;
            }
            // Wait 1 second before retrying
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
};

// Register endpoint
app.post('/register', async (req, res) => {
    try {
        const { name, email, phoneNumber, password } = req.body;

        // Validate input
        const validationErrors = validateRegistration(req.body);
        if (validationErrors.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed', 
                errors: validationErrors 
            });
        }

        // Check if user already exists
        const [existingUsers] = await pool.execute(
            'SELECT * FROM users WHERE email = ?',
            [email.toLowerCase().trim()]
        );
        
        if (existingUsers.length > 0) {
            return res.status(409).json({ 
                success: false, 
                message: 'User with this email already exists' 
            });
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert user into database
        await pool.execute(
            'INSERT INTO users (uname, email, phone, password, role) VALUES (?, ?, ?, ?, ?)',
            [
                name.trim(),
                email.toLowerCase().trim(),
                phoneNumber.trim(),
                hashedPassword,
                'USER'
            ]
        );

        // Return success response
        res.status(201).json({
            success: true,
            message: 'Register Success'
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Find user by email (username is treated as email)
        const [users] = await pool.execute(
            'SELECT * FROM users WHERE email = ?',
            [username.toLowerCase().trim()]
        );
        
        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const user = users[0];

        // Compare password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Generate JWT token
        const tokenPayload = {
            sub: user.email,
            role: user.role,
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours expiry
        };

        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
            algorithm: 'HS256'
        });

        // Set JWT as HTTP-only cookie
        res.cookie('jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours in milliseconds
        });

        // Send success response
        res.status(200).json({
            success: true,
            message: 'Login successful'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Logout endpoint
app.post('/logout', (req, res) => {
    res.clearCookie('jwt');
    res.status(200).json({
        success: true,
        message: 'Logout successful'
    });
});

// Protected route middleware
const authenticateToken = (req, res, next) => {
    const token = req.cookies.jwt;

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No token provided.'
        });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({
            success: false,
            message: 'Invalid or expired token'
        });
    }
};

// Dashboard endpoint (protected)
app.get('/dashboard', authenticateToken, (req, res) => {
    res.status(200).json({
        success: true,
        message: 'Dashboard data',
        user: {
            email: req.user.sub,
            role: req.user.role
        }
    });
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'Server is running'
    });
});

// Test endpoint
app.get('/', (req, res) => {
    res.send('hiii');
});

// Initialize database and start server
const startServer = async () => {
    let retries = 5;
    while (retries > 0) {
        try {
            await initializeDatabase();
            app.listen(PORT, () => {
                console.log(`Server is running on port ${PORT}`);
            });
            break; // Exit the loop on success
        } catch (error) {
            retries--;
            console.error(`Failed to start server (attempt ${6-retries}/5):`, error.message);
            if (retries === 0) {
                console.error('Failed to start server after 5 attempts');
                process.exit(1);
            }
            // Wait 3 seconds before retrying
            await new Promise(resolve => setTimeout(resolve, 3000));
        }
    }
};

startServer();

module.exports = app;
