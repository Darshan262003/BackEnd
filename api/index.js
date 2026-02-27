const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const { pool, initializeDatabase, createUser, findUserByEmail, checkUserExists, useDatabase } = require('../db');

const app = express();

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
    credentials: true
}));

// Initialize database on first request
let dbInitialized = false;
const ensureDbInitialized = async () => {
    if (!dbInitialized) {
        await initializeDatabase();
        dbInitialized = true;
    }
};

// Enhanced database initialization with retry mechanism for API routes
const ensureDbInitializedWithRetry = async () => {
    if (!dbInitialized) {
        let retries = 3;
        while (retries > 0) {
            try {
                await initializeDatabase();
                dbInitialized = true;
                break; // Exit the loop on success
            } catch (error) {
                retries--;
                console.error(`Database initialization in API route failed (attempt ${4-retries}/3):`, error.message);
                if (retries === 0) {
                    console.error('API route failed to connect to database after 3 attempts');
                    throw error;
                }
                // Wait 1 second before retrying
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
    }
};

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

// Register endpoint
app.post('/register', async (req, res) => {
    try {
        await ensureDbInitializedWithRetry();
        const { name, email, phoneNumber, password } = req.body;

        const validationErrors = validateRegistration(req.body);
        if (validationErrors.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'Validation failed', 
                errors: validationErrors 
            });
        }

        const userExists = await checkUserExists(email);
        
        if (userExists) {
            return res.status(409).json({ 
                success: false, 
                message: 'User with this email already exists' 
            });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        await createUser(name, email, phoneNumber, hashedPassword);

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
        await ensureDbInitializedWithRetry();
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        const user = await findUserByEmail(username);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        const secret = process.env.JWT_SECRET || 'fallback_secret_key_change_this_in_production';
        if (!secret || secret === 'your_super_secret_jwt_key_change_this_in_production') {
            console.warn('WARNING: Using default/fallback JWT secret. Please set a proper JWT_SECRET in your environment variables for production use.');
        }
        
        const tokenPayload = {
            sub: user.email,
            role: user.role,
            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60)
        };

        const token = jwt.sign(tokenPayload, secret, {
            algorithm: 'HS256'
        });

        res.cookie('jwt', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 24 * 60 * 60 * 1000
        });

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token: token
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
const authenticateToken = async (req, res, next) => {
    await ensureDbInitializedWithRetry();
    const token = req.cookies.jwt;

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access denied. No token provided.'
        });
    }

    try {
        const secret = process.env.JWT_SECRET || 'fallback_secret_key_change_this_in_production';
        const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
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
app.get('/dashboard', authenticateToken, async (req, res) => {
    try {
        await ensureDbInitializedWithRetry();
        res.status(200).json({
            success: true,
            message: 'Dashboard data',
            user: {
                email: req.user.sub,
                role: req.user.role
            }
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Root test endpoint
app.get('/', (req, res) => {
    res.send('hiii');
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        success: true,
        message: 'Server is running'
    });
});

module.exports = app;
