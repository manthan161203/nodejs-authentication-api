const express = require('express');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const fileUpload = require('express-fileupload');
const cors = require('cors');

const authRouters = require('./src/routers/authRouter');
const connectDB = require('./src/config/db');

dotenv.config();

const app = express();
const PORT = process.env.PORT;

// Call the connectDB function to create MongoDB connection
connectDB();

app.use(cors());

app.use(express.json());
app.use(express.static('public'));

app.use(fileUpload());
app.use(bodyParser.json());

app.use('/api/auth', authRouters);

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
