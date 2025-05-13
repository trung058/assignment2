require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;
const mongoUrl = process.env.MONGODB_URI;

// ------------------ Middleware ------------------
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        mongoUrl,
        crypto: { secret: process.env.MONGODB_SESSION_SECRET },
        ttl: 60 * 60
    }),
    resave: false,
    saveUninitialized: false
}));

function isAdmin(req, res, next) {
    if (!req.session.username || req.session.user_type !== 'admin') {
        return res.redirect('/login');
    }
    next();
}



// ------------------ Routes ------------------

// Home Page
app.get('/', (req, res) => {
  res.render('home', {
    title: 'Home',
    username: req.session.username,
    user_type: req.session.user_type,
    name: req.session.name
  });
});


// Signup
app.get('/signup', (req, res) => {
    res.render('signup', {
        title: "Signup",
        error: null,
        username: req.session.username,
        user_type: req.session.user_type
    });
});

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
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
        await users.insertOne({ name, email, password: hashedPassword, user_type: "user" });

        req.session.username = email;
        req.session.name = name;
        req.session.user_type = "user";

        await client.close();
        res.redirect('/members');
    } catch (err) {
        console.error(err);
        res.render('signup', { error: "Internal error occurred." });
    }
});

// Login
app.get('/login', (req, res) => {
    res.render('login', {
        title: "Login",
        error: null,
        username: req.session.username,
        user_type: req.session.user_type
    });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
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
        if (!user || !(await bcrypt.compare(password, user.password))) {
            await client.close();
            return res.render('login', { error: "Invalid credentials." });
        }

        req.session.username = email;
        req.session.name = user.name;
        req.session.user_type = user.user_type;

        await client.close();
        res.redirect('/members');
    } catch (err) {
        console.error(err);
        res.render('login', { error: "Internal error occurred." });
    }
});

// Members
app.get('/members', (req, res) => {
    if (!req.session.username) return res.redirect('/login');
    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg', 'cat4.jpg', 'cat5.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.render('members', {
        title: "Members",
        name: req.session.name,
        image: randomImage,
        username: req.session.username,
        user_type: req.session.user_type
    });
});

// Admin
app.get('/admin', isAdmin, async (req, res) => {
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    const users = await db.collection('users').find().toArray();
    await client.close();

    res.render('admin', {
        title: "Admin Panel",
        users,
        username: req.session.username,
        user_type: req.session.user_type
    });
});

// Promote/Demote
app.post('/promote', async (req, res) => {
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    await db.collection('users').updateOne({ email: req.body.email }, { $set: { user_type: 'admin' } });
    await client.close();
    res.redirect('/admin');
});

app.post('/demote', async (req, res) => {
    if (req.body.email === req.session.username) {
        return res.render('admin', {
            title: "Admin Panel",
            error: "You cannot demote yourself.",
            username: req.session.username,
            user_type: req.session.user_type
        });
    }
    const client = new MongoClient(mongoUrl);
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    await db.collection('users').updateOne({ email: req.body.email }, { $set: { user_type: 'user' } });
    await client.close();
    res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// 404 Catch-All
app.use((req, res) => {
  res.status(404).render('404', {
    title: '404 Not Found',
    username: req.session.username,
    user_type: req.session.user_type
  });
});


// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
