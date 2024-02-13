const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
    }
    catch (err) {
        console.error(' Failed to connect to MongoDB', err);
        process.exit(1);
    }
};

module.exports = connectDB;