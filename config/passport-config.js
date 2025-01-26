const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const sqlite3 = require('sqlite3');
const path = require('path');

const db = new sqlite3.Database('./database/Auth.db');

const dotenv = require('dotenv');

dotenv.config();

// Serialize user to store user ID in session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user to retrieve user details from database
passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
        if (err) {
            return done(err);
        }
        return done(null, row);
    });
});

// Configure Google OAuth Strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "http://localhost:3000/auth/google/callback",
        },
        (token, tokenSecret, profile, done) => {
            const email = profile.emails[0].value;
            const username = profile.displayName;
            const firstName = profile.name.givenName; // Google profile's first name
            const lastName = profile.name.familyName; // Google profile's last name

            // Check if user exists in the database
            db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                if (err) {
                    return done(err);
                }

                if (!row) {
                    // User doesn't exist, insert into database
                    db.run(
                        'INSERT INTO users (username, firstName, lastName, email, password, googleId) VALUES (?, ?, ?, ?, ?, ?) ',
                        [username, firstName, lastName, email, '', profile.id], // Password can remain blank since it's Google login
                        function (err) {
                            if (err) {
                                return done(err);
                            }
                            // Pass the newly created user to the callback
                            const newUser = {
                                id: this.lastID,
                                username,
                                firstName,
                                lastName,
                                email,
                                googleId: profile.id,
                            };
                            return done(null, newUser);
                        }
                    );
                } else {
                    // User exists, pass the user to the callback
                    return done(null, row);
                }
            });
        }
    )
);


module.exports = passport;
