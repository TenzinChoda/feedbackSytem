const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const nodemailer = require('nodemailer');
require('dotenv').config();

const saltRounds = 10;

// Render the signup page
exports.getSignUpPage = (req, res) => {
    res.render('pages/signup', { message: null });
};

// Email transporter setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Handle signup logic
exports.postSignUp = async (req, res) => {
    const { name, email, password, role } = req.body;

    try {
        // Check if user already exists
        const existingUser = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser) {
            return res.render('pages/signup', { message: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Generate verification token
        const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Insert user into the database
        await db.none(
            'INSERT INTO users (name, email, password, role, verification_token) VALUES ($1, $2, $3, $4, $5)',
            [name, email, hashedPassword, role || 'user', verificationToken]
        );

        // Send verification email
        const verificationLink = `${process.env.BASE_URL}/verify-email?token=${verificationToken}`;
        await transporter.sendMail({
            from: `"Bootcamp Auth" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Email Verification',
            html: `
                <p>Hi ${name},</p>
                <p>Thank you for signing up! Please verify your email by clicking the link below:</p>
                <a href="${verificationLink}">Verify Email</a>
                <p>If you did not sign up, please ignore this email.</p>
            `,
        });

        res.render('pages/signup', {
            message: 'Registration successful! Please check your email to verify your account.',
        });
    } catch (error) {
        console.error('Error during signup:', error);
        res.render('pages/signup', {
            message: 'An error occurred during registration. Please try again.',
        });
    }
};

// Email verification route
exports.verifyEmail = async (req, res) => {
    const { token } = req.query;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const email = decoded.email;

        await db.none('UPDATE users SET is_verified = true, verification_token = NULL WHERE email = $1', [email]);
        res.send('Email verified successfully! You can now log in.');
    } catch (error) {
        console.error('Verification error:', error);
        res.send('Invalid or expired verification link.');
    }
};

// Render login page
exports.getLoginPage = (req, res) => {
    res.render('pages/login', { message: null });
};

// Handle login logic
exports.postLogin = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (!user) {
            return res.render('pages/login', { message: 'Invalid email or password' });
        }

        if (!user.is_verified) {
            return res.render('pages/login', { message: 'Please verify your email before logging in.' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.render('pages/login', { message: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 3600000, // 1 hour
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
        });

        // Redirect based on role
        if (user.role === 'admin') {
            res.redirect('/admin/dashboard');
        } else {
            res.redirect('/user/dashboard');
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.render('pages/login', {
            message: 'An error occurred during login. Please try again.',
        });
    }
}
// render the forgot password page
exports.forgotPassword = async (req, res) => {
    res.render('pages/forgot_password', { message: null });
};

//handles forgot password logic
exports.postForgotPassword = async (req, res) => {
    const { email } = req.body;

    try{
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (!user) {
            return res.render('pages/forgot_password', { message: 'Email not registered' });
        }
        // Generate reset token
        const resetToken = jwt.sign({ email : user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // store reset token in the database
        await db.none('UPDATE users SET reset_token = $1 WHERE email = $2', [resetToken, email]);

        // Send reset email
        const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
        const mailoptions = {
            from: `"Bootcamp Auth" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset',
            html: `
                <p>Hi,</p>
                <p>You requested a password reset. Please click the link below to reset your password:</p>
                <a href="${resetLink}">Reset Password</a>
                <p>If you did not request this, please ignore this email.</p>
            `,
        };
        await transporter.sendMail(mailoptions);
        res.render('pages/forgot_password', { message: 'Password reset link sent to your email.' });
    }catch (error) {
        console.error('Error during forgot password:', error);
        res.render('pages/forgot_password', { message: 'An error occurred. Please try again.' });
    }
}

// render the reset password page
exports.getResetPasswordPage = (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.send('Invalid or missing password reset token.');
    }
    res.render('pages/reset_password', { message: null, token });
};

// Reset password logic
exports.resetPassword = async (req, res) => {
    const { token , newPassword} = req.body;
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [decoded.email]);
        if(!user){
            return res.render('pages/reset_password', { message: 'Invalid or expired token' });
        }

        // Hash new password 
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        //update the user's password and clear the reset token
        await db.none('UPDATE users SET password = $1, reset_token = NULL WHERE email = $2', [hashedPassword, user.email]);

        res.render('pages/reset_password', { message: 'Password reset successfully! You can now log in.', token: '' });
    }catch (error) {
        console.log('Error during password reset:', error);
        res.render('pages/reset_password', { message: 'Invalid or Expired token.' });

    }
}
// logic for logout
exports.logout = async(req, res) => {
    try{
        res.clearCookie('token');
        res.redirect('/login');
    }catch (error) {
        console.error('Error during logout:', error);
        res.status(500).send('An error occurred while logging out.');
    }
};