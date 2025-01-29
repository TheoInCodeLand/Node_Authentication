const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { check, validationResult } = require('express-validator');
const generateToken = require('../utils/generateToken');
const sendResetEmail = require('../utils/email');

const db = new sqlite3.Database(
    path.join(__dirname, '../database/Auth.db'),
    (err) => {
        if (err) {
            console.error('Error connecting to the database:', err.message);
            process.exit(1);
        }
        console.log('Connected to the SQLite database.');
    }
);

const router = express.Router();

router.get('/', (req, res) => {
    res.render('Auth/forgot-password', { error: null, message: null });
});

router.post(
    '/forgot-password',
    [check('email').isEmail().withMessage('Please enter a valid email.')],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('Auth/forgot-password', { error: errors.array()[0].msg, message: null });
        }
        const { email } = req.body;

        db.get("SELECT id FROM users WHERE email = ?", [email], (err, user) => {
            if (err || !user) {
                return res.render('Auth/forgot-password', {
                    error: null,
                    message: "If the email exists, a reset link has been sent.",
                });
            }

            const token = generateToken();
            const expiresAt = new Date(Date.now() + 3600000).toISOString(); // 1 hour expiration

            db.run(
                "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
                [token, expiresAt, user.id],
                (err) => {
                    if (err) {
                        return res.status(500).send("Error updating token.");
                    }

                    sendResetEmail(email, token);
                    res.render('Auth/forgot-password', {
                        error: null,
                        message: "If the email exists, a reset link has been sent.",
                    });
                    console.log(`Reset Token: ${token}`);
                }
            );
        });
    }
);

router.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;

    db.get(
        "SELECT id FROM users WHERE reset_token = ? AND reset_token_expires > ?",
        [token, new Date().toISOString()],
        (err, user) => {
            if (err || !user) {
                return res.render('Auth/reset-password', {
                    error: "Invalid or expired reset token.",
                    token: null,
                });
            }
            console.log("Valid Reset Token: ", token);
            res.render('Auth/reset-password', { error: null, token });
        }
    );
});

router.post(
    '/reset-password/:token',
    [
        check('password')
            .isLength({ min: 6 })
            .withMessage('Password must be at least 6 characters.'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        const { token } = req.params;
        const { password } = req.body;

        if (!errors.isEmpty()) {
            return res.render('Auth/reset-password', {
                error: errors.array()[0].msg,
                token,
            });
        }

        db.get(
            "SELECT id FROM users WHERE reset_token = ? AND reset_token_expires > ?",
            [token, new Date().toISOString()],
            async (err, user) => {
                if (err || !user) {
                    return res.render('Auth/reset-password', {
                        error: "Invalid or expired reset token.",
                        token: null,
                    });
                }

                const hashedPassword = await bcrypt.hash(password, 10);

                db.run(
                    "UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?",
                    [hashedPassword, user.id],
                    (err) => {
                        if (err) {
                            return res.status(500).send("Error resetting password.");
                        }
                        console.log("Password Reset Successful.");
                        res.redirect('/auth/sign-in');
                    }
                );
            }
        );
    }
);

module.exports = router;
