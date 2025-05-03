require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient } = require('mongodb');
const path = require('path');
const Joi = require('joi');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// mongodb connection string
const uri = `mongodb+srv://${process.env.MONGODB_USER}:${
  process.env.MONGODB_PASSWORD
}@${process.env.MONGODB_HOST}/${
  process.env.MONGODB_DATABASE
}?retryWrites=true&w=majority`;

// mongodb
const client = new MongoClient(uri, { useUnifiedTopology: true});

(async () => {
  await client.connect();
  const db    = client.db(process.env.MONGODB_DATABASE);
  const users = db.collection('users');

  // middleware
  app.use(express.urlencoded({ extended: true}));
  app.use(express.static(path.join(__dirname, 'public')));

  app.use(
    session({
      secret: process.env.NODE_SESSION_SECRET, 
      resave: false, 
      saveUninitialized: false, 
      cookie: { maxAge: 1000 * 60 * 60 }, 
      store: MongoStore.create({
        client, 
        collectionName: 'sessions',
        crypto: { secret: process.env.MONGODB_SESSION_SECRET }, 
        ttl: 60 * 60,
      }),
    })
  );

  const signupSchema = Joi.object({
    name     : Joi.string().max(30).required(),
    email    : Joi.string().email().required(),
    password : Joi.string().min(8).max(64).required()
  });

  const loginSchema = Joi.object({
    email    : Joi.string().email().required(),
    password : Joi.string().min(8).max(64).required()
  });

  function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/');
    next();
  }

  app.use((req, res, next) => {
    req.userCollection = db.collection('users');
    next();
  });

  // routes
  // home
  app.get('/', (req, res) => {
    if (!req.session.user) {
      return res.send(`
        <h1>Hello!</h1>
        <a href="/signup">Sign up</a> |
        <a href="/login">Log in</a>
      `);
    }
    res.send(`
      <h1>Hello, ${req.session.user.name}</h1>
      <a href="/members">Members</a> |
      <a href="/logout">Sign out</a>
    `);
  });

  // sign up form
  app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'views/signup.html'));
  });

  // handle sign up
  app.post('/signup', async (req, res) => {
    const { error, value } = signupSchema.validate(req.body);
    if (error)
      return res.status(400).send(`${error.message}<br><a href="/signup">Try again</a>`);

    if (await users.findOne({ email: value.email.toLowerCase() }))
      return res.status(400).send('Email already in use<br><a href="/signup">Try again</a>');

    const hashed = await bcrypt.hash(value.password, 10);
    await users.insertOne({ name: value.name, email: value.email.toLowerCase(), password: hashed });

    req.session.user = { name: value.name, email: value.email.toLowerCase() };
    res.redirect('/members');
  });

  // Log‑in form
  app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views/login.html')));

  // Handle log‑in
  app.post('/login', async (req, res) => {
    const { error, value } = loginSchema.validate(req.body);
    if (error)
      return res.status(400).send(`${error.message}<br><a href="/login">Try again</a>`);

    const user = await users.findOne({ email: value.email.toLowerCase() });
    if (!user || !(await bcrypt.compare(value.password, user.password)))
      return res.status(400).send('User and/or password not found<br><a href="/login">Try again</a>');

    req.session.user = { name: user.name, email: user.email };
    res.redirect('/members');
  });

  app.get('/members', requireLogin, (req, res) => {
    const pics = ['1.jpg', '2.jpg', '3.jpg'];               
    const img  = pics[Math.floor(Math.random() * pics.length)];
    res.send(`<h1>Hello, ${req.session.user.name}</h1>
      <img src="/images/${img}" alt="Random image"><br>
      <a href="/logout">Sign out</a>`);
  });

  app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
  });

  app.use((req, res) => {
    res.status(404).send('Page not found');
  });

  app.listen(PORT, () => {
    console.log(`Server on http://localhost:${PORT}`);
  });

})();

