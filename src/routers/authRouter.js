const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { check } = require('express-validator');

// Register user route
router.post('/register', [
    check('username', 'Please enter a valid username').not().isEmpty(),
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 }),
    check('phoneNumber', 'Please enter a valid phone number').isMobilePhone(),
    check('firstName', 'Please enter a valid first name').not().isEmpty(),
    check('lastName', 'Please enter a valid last name').not().isEmpty()
], authController.register);


module.exports = router;