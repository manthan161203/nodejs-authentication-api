const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { validationResult } = require('express-validator');

const User = require('../models/User');

const jwtSecret = crypto.randomBytes(32).toString('hex');

// Function to generate JWT token
const generateToken = (user) => {
    return jwt.sign({ id: user.id }, jwtSecret, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

const register = async (req, res) => {
    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, phoneNumber, password, firstName, lastName } = req.body;

        let user = await User.findOne({ username });

        // Check if user already exists
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Hash the password
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

        // Generate JWT Token
        const token = generateToken(user);

        res.status(200).json({ token });
    }
    catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

const login = async (req, res) => {
    try {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { emailOrUsername, password } = req.body;

        // Check if user exists by email
        let user = await User.findOne({ email: emailOrUsername });

        // If user not found by email, check by username
        if (!user) {
            user = await User.findOne({ username: emailOrUsername });
        }

        // Check if user exists
        if (!user) {
            return res.status(400).json({ msg: 'Invalid email or username' });
        }

        // Check if password is correct
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Password' });
        }

        // Generate JWT Token
        const token = generateToken(user);

        res.status(200).json({ token });
    }
    catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

module.exports = {
    register,
    login
};
