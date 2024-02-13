const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./src/config/db');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Call the connectDB function to create MongoDB connection
connectDB();

app.use(express.json());

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
