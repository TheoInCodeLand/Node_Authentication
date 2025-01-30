const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

async function sendResetEmail(email, token) {
    const resetLink = `http://localhost:3000/forgot-password/reset-password/${token}`;

    let mailOptions = {
        from: '"TheoInCodeLand | Auth" <' + process.env.EMAIL_USER + '>',
        to: email,
        subject: "Password Reset Request",
        html: `<p>You requested a password reset. Click below:</p>
               <a href="${resetLink}">${resetLink}</a>
               <p>The link will expire in an Hour, gnore if you didn’t request this.</p>`,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Password reset email sent to: ${resetLink}`, email );
    } catch (error) {
        console.error("Error sending email:", error);
    }
}

module.exports = sendResetEmail;
