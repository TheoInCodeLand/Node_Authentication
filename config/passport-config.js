const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const sqlite3 = require('sqlite3');
const path = require('path');

const db = new sqlite3.Database('./database/Auth.db');

const dotenv = require('dotenv');

dotenv.config();

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
        if (err) {
            return done(err);
        }
        return done(null, row);
    });
});

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "https://node-authentication-fx4o.onrender.com/auth/google/callback",
            // callbackURL: "https://localhost:3000/auth/google/callback",
            
        },
        (token, tokenSecret, profile, done) => {
            const email = profile.emails[0].value;
            const username = profile.displayName;
            const firstName = profile.name.givenName;
            const lastName = profile.name.familyName;

            db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
                if (err) {
                    return done(err);
                }

                if (!row) {
                    db.run(
                        'INSERT INTO users (username, firstName, lastName, email, password, googleId) VALUES (?, ?, ?, ?, ?, ?) ',
                        [username, firstName, lastName, email, '', profile.id],
                        function (err) {
                            if (err) {
                                return done(err);
                            }
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
                    return done(null, row);
                }
            });
        }
    )
);


module.exports = passport;
