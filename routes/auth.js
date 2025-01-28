const express = require('express');
const passport = require('passport');
const router = express.Router();
const sqlite3 = require('sqlite3');
const path = require('path');
const db = new sqlite3.Database('./database/Auth.db');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');

// Google Login Route
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google Callback Route
router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/auth/sign-in' }),
    (req, res) => {
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

// In-memory object to track failed login attempts
const loginAttempts = new Map(); // Use email as key

const MAX_ATTEMPTS = 3;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

router.post('/login', (req, res) => {
    const { email, password } = req.body;

    console.log(`Login attempt: Email/Username - ${email}`);

    if (!email || !password) {
        console.log('Login failed: Missing fields');
        return res.render('Auth/login', { error: 'All fields are required!' });
    }

    // Check if user is locked out
    if (loginAttempts.has(email)) {
        const { attempts, lockedUntil } = loginAttempts.get(email);

        if (lockedUntil && lockedUntil > Date.now()) {
            const remainingTime = Math.ceil((lockedUntil - Date.now()) / 60000);
            return res.render('Auth/login', {
                error: `Account locked. Try again in ${remainingTime} minute(s).`,
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
                handleFailedAttempt(email, res);
                return;
            }

            const passwordMatch = bcrypt.compareSync(password, user.password);

            if (!passwordMatch) {
                console.log('Login failed: Incorrect password');
                handleFailedAttempt(email, res);
                return;
            }

            // Successful login, reset attempts
            loginAttempts.delete(email);

            req.session.user = { id: user.id, username: user.username, email: user.email };

            console.log(`Login successful: User ID - ${user.id}, Username - ${user.username}`);
            res.redirect('/dashboard');
        }
    );
});

// Helper function to handle failed login attempts
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
    res.render('Auth/login', { error: 'Invalid credentials!' });
}

// Registration Route with Validation
router.post(
  '/register',
  [
    body('fname').notEmpty().withMessage('First name is required'),
    body('lname').notEmpty().withMessage('Last name is required'),
    body('email').isEmail().withMessage('Enter a valid email'),
    body('uname').notEmpty().withMessage('Username is required'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters long'),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('Auth/register', { error: errors.array()[0].msg });
    }

    const { fname, lname, email, uname, password } = req.body;

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error(err.message);
        return res.render('Auth/register', { error: 'Something went wrong. Please try again.' });
      }

      db.run(
        `
        INSERT INTO users (username, firstName, lastName, email, password, googleId, createdAt)
        VALUES (?, ?, ?, ?, ?, '0000000', ?)
        `,
        [uname, fname, lname, email, hashedPassword, new Date().toISOString()],
        (err) => {
          if (err) {
            console.error(err.message);
            if (err.message.includes('UNIQUE')) {
              return res.render('Auth/register', { error: 'Username or email already exists!' });
            }
            return res.render('Auth/register', { error: 'Something went wrong. Please try again.' });
          }
          res.redirect('/auth/sign-in');
        }
      );
    });
  }
);


module.exports = router;
