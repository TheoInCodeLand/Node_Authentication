const express = require('express');
const passport = require('./config/passport-config'); 
const session = require('express-session');
const authRoutes = require('./routes/auth'); // Import the authentication routes
const dotenv = require('dotenv');
const path = require('path');
const sqlite3 = require('sqlite3');
const fs = require('fs');

// Initialize dotenv to use environment variables
dotenv.config();
const app = express();

// Set up view engine (EJS)
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to parse the request body
app.use(express.urlencoded({ extended: true }));

// Initialize session middleware
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'default_secret', // Fallback for missing environment variable
        resave: false,
        saveUninitialized: true,
    })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/auth', authRoutes);

// Serve the dashboard after successful login
app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.render('index');
    } else {
        res.redirect('/auth/sign-in'); // Corrected path to match your routes
    }
});

app.use((req, res) => {
    res.status(404).render('404', { message: 'Page not found' }); // Ensure you have a 404.ejs file in your views
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
