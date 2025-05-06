require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// MongoDB URL and session secret from .env

const mongoUrl = process.env.MONGODB_URI;


// Middleware
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        mongoUrl: mongoUrl,
        crypto: { secret: process.env.MONGODB_SESSION_SECRET },
        ttl: 60 * 60 // 1 hour
    }),
    resave: false,
    saveUninitialized: false
}));

// -------------------- ROUTES --------------------

app.get('/', (req, res) => {
    res.render('home', {
      username: req.session.username,
      name: req.session.name
    });
  });
  

// GET Home Page
app.get('/', (req, res) => {
    if (!req.session.username) {
        res.render('index', { loggedIn: false });
    } else {
        res.render('index', { loggedIn: true, name: req.session.name });
    }
});



// GET Signup Page
app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

const { MongoClient } = require('mongodb');

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    // Basic field check
    if (!name || !email || !password) {
        return res.render('signup', { error: "All fields are required." });
    }

    // Joi validation to prevent NoSQL injection
    const schema = Joi.object({
        name: Joi.string().max(30).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).max(30).required()
    });

    const validation = schema.validate({ name, email, password });
    if (validation.error) {
        return res.render('signup', { error: "Invalid input format." });
    }

    try {
        const client = new MongoClient(mongoUrl);
        await client.connect();
        const db = client.db(process.env.MONGODB_DATABASE);
        const users = db.collection('users');

        const existingUser = await users.findOne({ email });
        if (existingUser) {
            await client.close();
            return res.render('signup', { error: "Email is already registered." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await users.insertOne({ name, email, password: hashedPassword });

        // Save session
        req.session.username = email;
        req.session.name = name;

        await client.close();
        res.redirect('/members');

    } catch (err) {
        console.error(err);
        res.render('signup', { error: "Internal error occurred. Please try again." });
    }
});



// GET Login Page
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// GET Members Page
app.get('/members', (req, res) => {
    if (!req.session.username) {
        return res.redirect('/');
    }

    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg', 'cat4.jpg', 'cat5.jpg']; // use your own image filenames
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.render('members', { name: req.session.name, image: randomImage });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Joi validation to prevent NoSQL injection
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(6).max(30).required()
    });

    const validation = schema.validate({ email, password });
    if (validation.error) {
        return res.render('login', { error: "Invalid input format." });
    }

    try {
        const client = new MongoClient(mongoUrl);
        await client.connect();
        const db = client.db(process.env.MONGODB_DATABASE);
        const users = db.collection('users');

        const user = await users.findOne({ email });

        if (!user) {
            await client.close();
            return res.render('login', { error: "User not found." });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            await client.close();
            return res.render('login', { error: "Invalid password." });
        }

        // Login success
        req.session.username = email;
        req.session.name = user.name;

        await client.close();
        res.redirect('/members');

    } catch (err) {
        console.error(err);
        res.render('login', { error: "Internal error occurred." });
    }
});


// GET Logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get('/', (req, res) => {
    res.redirect('/login');
  });
  

// 404 Catch-All
app.use((req, res) => {
    res.status(404).render('404');
});

// ------------------ START SERVER ------------------

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

app.get('/members', (req, res) => {
    if (!req.session.username) {
        return res.redirect('/');
    }

    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg']; // replace with your image filenames
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.render('members', { name: req.session.name, image: randomImage });
});


app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Session destruction error:", err);
        }
        res.redirect('/');
    });
});
   
app.use((req, res) => {
    res.status(404).render('404');
});

app.get('/', (req, res) => {
    res.render('login'); // or signup
  });
  

  