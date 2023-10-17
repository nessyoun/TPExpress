const express = require('express');
const mongoose = require('mongoose');
const app = express();
const port = process.env.PORT || 3000;
const flash = require('connect-flash');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const expressSession = require('express-session');

app.set('view engine', 'pug');
app.use(express.urlencoded({ extended: false }));
app.use(flash());
// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/nodeTP', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// User schema and model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});

const Utilisateur = mongoose.model('user', userSchema);

// Passport.js configuration
app.use(expressSession({ secret: 'your-secret-key', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
      const user = await Utilisateur.findById(id);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });
  

passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const user = await Utilisateur.findOne({ username });

      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    } catch (err) {
      return done(err);
    }
  }
));

// Routes
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 10;

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  try {
    const user = new Utilisateur({ username, password: hashedPassword });
    await user.save();
    res.status(201).send('User registered successfully');
  } catch (error) {
    res.status(400).send('Registration failed');
  }
});

app.get('/login',  (req, res) => {
    res.render('login');
});

app.post('/login',
    passport.authenticate('local', {
    successRedirect: '/books',
    failureRedirect: '/login',
    failureFlash: true,
  })
);

app.get('/books', (req, res) => {
    if (req.isAuthenticated()) {
        // Display a success flash message
        req.flash('success', 'You are logged in!');
        res.render('books');
      } else {
        // Display an error flash message
        req.flash('error', 'Please log in first.');
        res.redirect('/login');
      }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
