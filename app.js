const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/authRoutes');
const cookieParser = require('cookie-parser');
const { requireAuth, checkUser } = require('./middleware/authMiddleware');
require('dotenv').config();  

const app = express();

// middleware
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

// view engine
app.set('view engine', 'ejs');

// database connection
const dbURI = process.env.DB_URI;  
const port = process.env.PORT || 3000;  // Use the PORT environment variable if available, otherwise default to 3000
mongoose.connect(dbURI)
  .then((result) => app.listen(port, () => console.log(`Server is running on port ${port}`)))
  .catch((err) => console.log(err));

// routes
app.get('*', checkUser);
app.get('/', (req, res) => res.render('home'));
app.get('/destinations', requireAuth, (req, res) => res.render('destinations'));
app.use(authRoutes);
