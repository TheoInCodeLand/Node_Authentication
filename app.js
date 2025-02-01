const express = require('express');
const passport = require('./config/passport-config'); 
const session = require('express-session');
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

app.use(session({
    secret: 'your_secret_key', // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24-hour session
}));

function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next(); // User is logged in, proceed
    }
    res.redirect('/auth/sign-in'); // Redirect to login if not authenticated
}

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Routes
const authRoutes = require('./routes/auth');
app.use('/auth', authRoutes);

const forgotPasswordRoutes = require('./routes/forgot-password');
app.use('/forgot-password', forgotPasswordRoutes);

app.get('/', isAuthenticated, (req, res) => {
        res.render('index');
});

app.use((req, res) => {
    res.status(404).render('404', { error:'404', message: 'Page not found' }); // Ensure you have a 404.ejs file in your views
});

app.use((err, req, res, next) => {
    console.error(err.stack); // Log the error stack trace for debugging
    res.status(500).render('404', { error:'505', message: 'Something went wrong!' }); // Ensure you have an error.ejs file in your views
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
