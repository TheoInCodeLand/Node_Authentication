const express = require('express');
const nodemailer = require('nodemailer');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const path = require('path');
const sqlite3 = require('sqlite3');
const session = require('express-session'); // Required for session management
const { body, validationResult } = require('express-validator');
const otpGenerator = require('otp-generator');
require('dotenv').config();

const router = express.Router();
const db = new sqlite3.Database('./database/Auth.db');

// Configure Express Session
router.use(session({
    secret: 'your_secret_key', // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 } // 24-hour session
}));

function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next(); // User is logged in, proceed
    }
    res.redirect('/auth/sign-in'); // Redirect to login if not authenticated
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Google OAuth Login
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google Callback
router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/auth/sign-in' }),
    (req, res) => {
        req.session.user = req.user; // Store user in session
        res.redirect('/');
    }
);

// Render Login Page
router.get('/sign-in', (req, res) => {
    res.render('Auth/login', { error: null });
});

// Render Register Page
router.get('/sign-up', (req, res) => {
    res.render('Auth/register');
});

// Login Attempt Tracking
const loginAttempts = new Map();
const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

// Login Route
router.post('/login', (req, res) => {
    const { email, password } = req.body;

    console.log(`Login attempt: Email - ${email}`);

    if (!email || !password) {
        return res.render('Auth/login', { error: 'All fields are required!' });
    }
    // Check if user is locked out
    if (loginAttempts.has(email)) {
        const { attempts, lockedUntil } = loginAttempts.get(email);
        if (lockedUntil && lockedUntil > Date.now()) {
            const remainingTime = Math.ceil((lockedUntil - Date.now()) / 60000);
            return res.render('Auth/login', {
                error: `Account locked. Try again in ${remainingTime} minutes.`,
            });
        }
    }
    // Fetch user from the database
    db.get(
        `SELECT * FROM users WHERE email = ? OR username = ?`,
        [email, email],
        (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.render('Auth/login', { error: 'Something went wrong, please try again.' });
            }

            if (!user) {
                console.log('Login failed: User not found');
                return handleFailedAttempt(email, res);
            }

            const passwordMatch = bcrypt.compareSync(password, user.password);
            if (!passwordMatch) {
                console.log('Login failed: Incorrect password');
                return handleFailedAttempt(email, res);
            }
            // Successful login - reset attempts
            loginAttempts.delete(email);
            // Store user session
            req.session.user = {
                id: user.id,
                name: user.firstName,
                surname: user.lastName,
                username: user.username,
                email: user.email,
                phone: user.phone || null,
                address: user.address || null
            };

            console.log(`Login successful: User ID - ${user.id}, Username - ${user.username}`);

            res.redirect('/');
        }
    );
});

// Helper function for failed login attempts
function handleFailedAttempt(email, res) {
    if (!loginAttempts.has(email)) {
        loginAttempts.set(email, { attempts: 1, lockedUntil: null });
    } else {
        const { attempts, lockedUntil } = loginAttempts.get(email);

        if (lockedUntil && lockedUntil > Date.now()) {
            const remainingTime = Math.ceil((lockedUntil - Date.now()) / 60000);
            return res.render('Auth/login', {
                error: `Account locked. Try again in ${remainingTime} minute(s).`,
            });
        }

        const newAttempts = attempts + 1;

        if (newAttempts >= MAX_ATTEMPTS) {
            console.log(`Account locked: Email - ${email}`);
            loginAttempts.set(email, { attempts: newAttempts, lockedUntil: Date.now() + LOCKOUT_DURATION });
            return res.render('Auth/login', {
                error: `Too many failed attempts. Account locked for 15 minutes.`,
            });
        }

        loginAttempts.set(email, { attempts: newAttempts, lockedUntil: null });
    }

    console.log(`Login failed: ${email} - Attempts: ${loginAttempts.get(email).attempts}`);
    return res.render('Auth/login', { error: 'Invalid credentials!' });
}

// Logout Route
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.redirect('/auth/sign-in');
    });
});

// Registration Route with Validation
router.post(
    '/register',
    [
        body('fname').notEmpty().withMessage('First name is required'),
        body('lname').notEmpty().withMessage('Last name is required'),
        body('email').isEmail().withMessage('Enter a valid email'),
        body('uname').notEmpty().withMessage('Username is required'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('Auth/register', { error: errors.array()[0].msg });
        }

        const { fname, lname, email, uname, password } = req.body;

        // Check if email or username already exists
        db.get(`SELECT * FROM users WHERE email = ? OR username = ?`, [email, uname], async (err, user) => {
            if (user) {
                return res.render('Auth/register', { error: 'Email or username already exists!' });
            }

            const otp = otpGenerator.generate(6, { upperCase: false, specialChars: false });
            const expiresAt = Date.now() + 3 * 60 * 1000; // OTP expires in 3 minutes

            req.session.tempUser = { fname, lname, email, uname, password, otp, expiresAt };

            const mailOptions = {
                from: 'thobejanetheo@gmail.com',
                to: email,
                subject: 'Verify Your Email - OTP Code',
                text: `Your OTP code is: ${otp} to complete your TheoInCodeLand account registration request. Code valid for 5 minutes.`
            };
            console.log('Verification email sent.')
            transporter.sendMail(mailOptions, (error) => {
                if (error) {
                    return res.render('Auth/register', { error: 'Error sending OTP. Please try again.' });
                }
                res.redirect('/auth/verify-email'); // Redirect to OTP verification page
            });
        });
    }
);

// Step 2: Render OTP Verification Page
router.get('/verify-email', (req, res) => {
    if (!req.session.tempUser) {
        return res.redirect('/auth/sign-up');
    }
    res.render('Auth/OTP', { error: null });
});

// Step 3: Verify OTP and Save User in Database
router.post('/verify-email', async (req, res) => {
    const { otp } = req.body;

    if (!req.session.tempUser) {
        return res.render('Auth/OTP', { error: 'Session expired. Please register again.' });
    }

    const { fname, lname, email, uname, password, otp: storedOtp, expiresAt } = req.session.tempUser;

    if (Date.now() > expiresAt) {
        return res.render('Auth/OTP', { error: 'OTP expired. Please register again.' });
    }
    if (otp !== storedOtp) {
        return res.render('Auth/OTP', { error: 'Invalid OTP. Try again.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        `INSERT INTO users (username, firstName, lastName, email, password, googleId, createdAt)
        VALUES (?, ?, ?, ?, ?, '0000000', ?)`,
        [uname, fname, lname, email, hashedPassword, new Date().toISOString()],
        (err) => {
            if (err) {
                return res.render('Auth/OTP', { error: 'Error saving user. Please try again.' });
            }

            delete req.session.tempUser;
            res.redirect('/auth/sign-in');
        }
    );
});

module.exports = router;
