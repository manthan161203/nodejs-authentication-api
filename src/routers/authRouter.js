const express = require('express');
const router = express.Router();
const { check } = require('express-validator');

const verifyToken = require('../config/authMiddleware');
const authController = require('../controllers/authController');

// Route to register a new user
router.post('/register', [
    check('username', 'Please enter a valid username').not().isEmpty(),
    check('email', 'Please enter a valid email').isEmail(),
    check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 }),
    check('phoneNumber', 'Please enter a valid phone number').isMobilePhone(),
    check('firstName', 'Please enter a valid first name').not().isEmpty(),
    check('lastName', 'Please enter a valid last name').not().isEmpty()
], authController.register);

// Route to login user
router.post('/login', [
    check('emailOrUsername', 'Please enter a valid email or username').notEmpty(),
    check('password', 'Password is required').exists()
], authController.login);

// Route to change password
router.post('/change-password', verifyToken, [
    check('emailOrUsername', 'Please enter a valid email or username').notEmpty(),
    check('oldPassword', 'Old password is required').notEmpty(),
    check('newPassword', 'New password is required').notEmpty().isLength({ min: 6 })
], authController.changePassword);

// Route to send OTP via Mail for forget password
router.post('/forget-password', [
    check('email', 'Please enter a valid email').notEmpty(),
], authController.forgotPassword);

// Route to reset password
router.post('/reset-password', [
    check('email', 'Please enter a valid email').notEmpty(),
    check('newPassword', 'New password is required').notEmpty().isLength({ min: 6 })
], authController.resetPassword);

// Route to view user profile
router.post('/profile', verifyToken, authController.viewProfile);

// Route to view user profile
router.post('/users', verifyToken, authController.getAllUsers);

module.exports = router;