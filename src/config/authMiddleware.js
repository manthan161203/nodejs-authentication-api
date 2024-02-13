const jwt = require('jsonwebtoken');

const { jwtSecret } = require('../controllers/authController')

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization;

    console.log(token);

    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

module.exports = verifyToken;
