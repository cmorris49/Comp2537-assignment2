require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient } = require('mongodb');
const path = require('path');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const app = express();
app.set('view engine', 'ejs');
const PORT = process.env.PORT || 3000;

// mongodb connection string
const uri = `mongodb+srv://${process.env.MONGODB_USER}:${
  process.env.MONGODB_PASSWORD
}@${process.env.MONGODB_HOST}/${
  process.env.MONGODB_DATABASE
}?retryWrites=true&w=majority`;

// mongodb
const client = new MongoClient(uri);

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

  function validate(schema, source = 'body') {
    return (req, res, next) => {
      const { error, value } = schema.validate(req[source], {
        abortEarly: false,   
        stripUnknown: true,  
      });
      if (error) {
        const msg = error.details.map(d => d.message).join('<br>');
        const view = req.path.includes('signup') ? 'signup' : 'login';
        return res.status(400).render(view, { error: msg });
      }
      req[source] = value; 
      next();
    };
  }

  function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
  }

  function requireLoginHome(req, res, next) {
    if (!req.session.user) return res.redirect('/');   
    next();
  }

  function requireAdmin(req, res, next) {
    if (!req.session.user) {
      return res.redirect('/login');
    }
    if (req.session.user.user_type !== 'admin') {
      return res.status(403).render('403', {
        message: 'You need to be an admin to view this page.'
      });
    }
    next();
  }

  app.use((req, res, next) => {
    req.userCollection = db.collection('users');
    next();
  });

  // routes
  // home
  app.get('/', (req, res) =>
    res.render('index', { user: req.session.user })
  );

  // sign up form
  app.get('/signup', (req, res) => res.render('signup', { error: null }));

  app.post('/signup', validate(signupSchema, 'body'), async (req, res) => {
    const { name, email, password } = req.body;
    const existing = await users.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res
        .status(400)
        .render('signup', { error: 'Email already in use. Try a different email.' });
    }
    const hashed = await bcrypt.hash(password, 10);
    await users.insertOne({
      name,
      email: email.toLowerCase(),
      password: hashed,
      user_type: 'user'
    });
    req.session.user = { name, email: email.toLowerCase(), user_type: 'user' };
    res.redirect('/members');
    }
  );

  // Log‑in form
  app.get('/login', (req, res) => res.render('login', { error: null }));

  app.post('/login', validate(loginSchema, 'body'), async (req, res) => {
      const { email, password } = req.body;
      const user = await users.findOne({ email: email.toLowerCase() });
      if (!user) {
        return res
          .status(400)
          .render('login', { error: 'No account exists with that email.' });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res
          .status(400)
          .render('login', { error: 'Incorrect password. Please try again.' });
      }
      req.session.user = {
        name: user.name,
        email: user.email,
        user_type: user.user_type
      };
      res.redirect('/members');
    }
  );

  app.get('/members', requireLoginHome, (req, res) => {
    const pics = ['1.jpg','2.jpg','3.jpg'];
    res.render('members', { user: req.session.user, images: pics });
  });

  app.get('/admin', requireLogin, requireAdmin, async (req,res) => {
    const allUsers = await users.find().toArray();
    res.render('admin', { users: allUsers, currentName: req.session.user.name });
  });

  app.get('/admin/promote/:name', requireLogin, requireAdmin, async (req, res) => {
      await users.updateOne(
        { name: req.params.name },
        { $set: { user_type: 'admin' } }
      );
      res.redirect('/admin');
    }
  );

  app.get('/admin/demote/:name', requireLogin, requireAdmin, async (req, res) => {
      await users.updateOne(
        { name: req.params.name },
        { $set: { user_type: 'user' } }
      );
      res.redirect('/admin');
    }
  );

  app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
  });

  app.use((req, res) => {
    res.status(404).render('404');
  });
  
  app.listen(PORT, () => {
    console.log(`Server on http://localhost:${PORT}`);
  });

})();

