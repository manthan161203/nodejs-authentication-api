const express = require('express');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const authRouters = require('./src/routers/authRouter');
const connectDB = require('./src/config/db');

dotenv.config();

const app = express();
const PORT = process.env.PORT;

// Call the connectDB function to create MongoDB connection
connectDB();

app.use(express.static('public'));
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use('/api/auth', authRouters);

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
