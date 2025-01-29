const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator'); // For validation

// Forgot password page
router.get('/', (req, res) => {
    res.render('Auth/forgot-password', { error: null });
});

// Handle forgot password form submission
router.post('/forgot-password', [
    check('email').isEmail().withMessage('Please enter a valid email address.')
], (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.render('forgot-password', {
            error: errors.array()[0].msg, // Show the first error
        });
    }

    // Here, you would normally send a password reset link to the user's email.
    // For demonstration purposes, we will assume the email is valid.
    const { email } = req.body;

    // Generate a password reset token (in a real scenario, use a library like crypto)
    const resetToken = 'random-token';  // Use a real token generation strategy

    // Example: Save the resetToken in the database (replace with actual logic)
    // sendPasswordResetEmail(email, resetToken);

    // In this example, we're simply redirecting to the reset password page with the token
    res.redirect(`/reset-password/${resetToken}`);
});

// Reset password page
router.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    // Normally, you would validate the token here (e.g., check it in the database)
    res.render('reset-password', { token });
});

// Handle reset password form submission
router.post('/reset-password/:token', [
    check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters.')
], (req, res) => {
    const errors = validationResult(req);
    const { token } = req.params;

    if (!errors.isEmpty()) {
        return res.render('reset-password', {
            error: errors.array()[0].msg, 
            token
        });
    }

    // Here, you would normally update the user's password in the database
    const { password } = req.body;

    // Example: Update the password in the database (replace with actual logic)
    // updateUserPassword(token, password);

    // After successfully updating the password, redirect to login page
    res.redirect('/auth/login');
});

module.exports = router;
