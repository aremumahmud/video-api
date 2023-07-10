const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

// Create an Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded())
    //crypto
const crypto = require('crypto');

const algorithm = 'aes-256-cbc';
const key = 'encryption_key'; // Replace with a strong encryption key
const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(encrypted) {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}
// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/testdb7', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    zipCode: String,
    address: String,
    cardDetails: String, // Encrypted card details will be stored here
});


const User = mongoose.model('User', userSchema);

// Define the routes
app.post('/login', async(req, res) => {
    const { username, password } = req.body;

    // Check if the user exists
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Check the password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ username: user.username }, 'secretkey');

    res.json({ token });
});

app.get('/carddetails/:username', async(req, res) => {
    const { username } = req.params;

    // Find the user
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    // Decrypt and retrieve the card details
    const decryptedCardDetails = decrypt(user.cardDetails);

    res.status(200).json(JSON.parse(decryptedCardDetails));
});

app.post('/signup', async(req, res) => {
    const { username, password, zipCode, address } = req.body;
    console.log(req.body)
    if (!username || !password || !zipCode || !address) return res.status(409).json({ message: 'fields missing' });

    // Check if the user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(409).json({ message: 'Username already exists' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create a new user
    const newUser = new User({
        username,
        password: hashedPassword,
        zipCode,
        address,
    });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
});


app.post('/carddetails', async(req, res) => {

    const { username, cardNumber, cardHolder, expirationDate, cvv } = req.body;
    if (!username || !cardNumber || !cardHolder || !expirationDate || !cvv) return res.status(409).json({ message: 'fields missing' });
    // Find the user
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    // Encrypt the card details
    const encryptedCardDetails = encrypt(
        JSON.stringify({
            cardNumber,
            cardHolder,
            expirationDate,
            cvv,
        })
    );

    // Store the encrypted card details
    user.cardDetails = encryptedCardDetails;
    await user.save();

    res.status(200).json({ message: 'Card details stored successfully' });
});


// Start the server
app.listen(3000, () => {
    console.log('Server listening on port 3000');
});