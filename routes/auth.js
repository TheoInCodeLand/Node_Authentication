const express = require('express');
const passport = require('passport');
const router = express.Router();
const sqlite3 = require('sqlite3');
const path = require('path');
const db = new sqlite3.Database('./database/Auth.db');
// Google Login Route
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google Callback Route
router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/auth/sign-in' }),
    (req, res) => {
        res.redirect('/'); // Successful login redirects to the dashboard
    }
);

// Render Login Page
router.get('/sign-in', (req, res) => {
    res.render('Auth/login');
});

// Render Register Page
router.get('/sign-up', (req, res) => {
    res.render('Auth/register');
});

// Handle Login
router.post('/login', (req, res, next) => {
    const { email, password } = req.body;

    // Find user by email
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).send('Database error');
        }
        if (!user) {
            return res.status(400).send('Invalid email or password');
        }

        // Compare passwords
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error comparing passwords');
            }

            if (isMatch) {
                req.login(user, (err) => {
                    if (err) {
                        console.error(err.message);
                        return res.status(500).send('Error logging in');
                    }
                    return res.redirect('/dashboard'); // Redirect to a protected page after login
                });
            } else {
                return res.status(400).send('Invalid email or password');
            }
        });
    });
});

// Handle Registration
router.post('/register', (req, res) => {
    const { username, password, name, surname, email, phone, address, age } = req.body;

    // Input validation
    if (!username || !password || !name || !surname || !email || !phone || !address || !age) {
        return res.render('Auth/register', { error: 'All fields are required!' });
    }

    if (password.length < 6) {
        return res.render('Auth/register', { error: 'Password must be at least 6 characters long!' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    // Insert user into the database
    db.run(
        `
        INSERT INTO users (username, password, name, surname, email, phone, address, age, role)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'customer')
        `,
        [username, hashedPassword, name, surname, email, phone, address, age],
        (err) => {
            if (err) {
                console.error(err.message);
                if (err.message.includes('UNIQUE')) {
                    return res.render('Auth/register', { error: 'Username or email already exists!' });
                }
                return res.render('Auth/register', { error: 'Something went wrong. Please try again.' });
            }
            res.redirect('/auth/sign-in'); // Redirect to login page after successful registration
        }
    );
});

module.exports = router;
