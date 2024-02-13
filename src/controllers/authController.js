const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const { validationResult } = require('express-validator');
const sendOTPViaEmail = require('../services/nodeMailer');

const User = require('../models/User');

// To generate a secure secret key
const jwtSecret = crypto.randomBytes(32).toString('hex');

// Controller function to generate JWT token
const generateToken = (user) => {
    return jwt.sign({ id: user.id }, jwtSecret, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

// Controller function to generate OTP
const generateOTP = () => {
    // Generating a random 4-digit OTP
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    return otp;
};

// Controller function to register a new user
const register = async (req, res) => {
    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, phoneNumber, password, firstName, lastName } = req.body;

        let user = await User.findOne({ username });

        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({
            username,
            email,
            phoneNumber,
            password: hashedPassword,
            firstName,
            lastName
        });

        await user.save();

        const token = generateToken(user);

        res.status(200).json({ token });
    }
    catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Controller function to handle user login
const login = async (req, res) => {
    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { emailOrUsername, password } = req.body;

        let user = await User.findOne({ $or: [{ email: emailOrUsername }, { username: emailOrUsername }] });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid email or username' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Password' });
        }

        const token = generateToken(user);

        res.status(200).json({ token });
    }
    catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Controller function to handle password change
const changePassword = async (req, res) => {
    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { emailOrUsername, oldPassword, newPassword } = req.body;

        let user = await User.findOne({ $or: [{ email: emailOrUsername }, { username: emailOrUsername }] });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid email or username' });
        }

        const isMatch = await bcrypt.compare(oldPassword, user.password);

        if (!isMatch) {
            return res.status(400).json({ msg: 'Incorrect old password' });
        }

        if (oldPassword === newPassword) {
            return res.status(400).json({ msg: 'New password must be different from old password' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        user.password = hashedPassword;
        await user.save();

        const subject = 'Password Changed';
        const text = `Your password has been successfully changed. Your new password is: ${newPassword}`;
        await sendOTPViaEmail(user.email, subject, text);

        res.status(200).json({ msg: 'Password changed successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Controller function to handle forgot password request
const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User with this email does not exist' });
        }

        const OTP = generateOTP();

        const subject = 'Password Reset OTP';
        const text = `Your OTP (One-Time Password) for password reset is: ${OTP}`;
        await sendOTPViaEmail(email, subject, text);

        user.otp = OTP;

        await user.save();

        res.status(200).json({ message: 'OTP sent successfully' });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ message: 'Server Error' });
    }
};

// Controller function to handle password reset
const resetPassword = async (req, res) => {
    try {
        const { email, OTP, newPassword } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'User with this email does not exist' });
        }

        if (user.otp !== OTP) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        user.password = hashedPassword;
        user.otp = undefined;
        await user.save();

        const subject = 'Password Reset Successful';
        const text = `Your password has been successfully reset. Your new password is: ${newPassword}`;
        await sendOTPViaEmail(email, subject, text);

        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ message: 'Server Error' });
    }
};

// Controller function to view user profile
const viewProfile = async (req, res) => {
    try {
        const { emailOrUsername } = req.body;

        const user = await User.findOne({ $or: [{ email: emailOrUsername }, { username: emailOrUsername }] }).select('-password');

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        res.status(200).json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Controller function to get all users
const getAllUsers = async (req, res) => {
    try {

        const users = await User.find().select('-password');

        if (!users) {
            return res.status(404).json({ message: 'No users found' });
        }

        res.status(200).json(users);
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ message: 'Server Error' });
    }
};

module.exports = {
    jwtSecret,
    register,
    login,
    changePassword,
    forgotPassword,
    resetPassword,
    viewProfile,
    getAllUsers
};
