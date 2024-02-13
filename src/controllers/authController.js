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
        console.error(err);
        res.status(500).send('Server Error');
    }
};

module.exports = {
    register,
};
