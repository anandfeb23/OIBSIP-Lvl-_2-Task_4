const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware to require authentication
const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;

  // Check if the JWT exists and is verified
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
      if (err) {
        console.error(`JWT verification error: ${err.message}`);
        res.redirect('/login');
      } else {
        console.log(`JWT verified: ${decodedToken}`);
        next();
      }
    });
  } else {
    res.redirect('/login');
  }
};

// Middleware to check current user
const checkUser = (req, res, next) => {
  const token = req.cookies.jwt;

  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
      if (err) {
        res.locals.user = null;
        next();
      } else {
        try {
          const user = await User.findById(decodedToken.id);
          res.locals.user = user;
        } catch (error) {
          console.error(`Error fetching user: ${error.message}`);
          res.locals.user = null;
        }
        next();
      }
    });
  } else {
    res.locals.user = null;
    next();
  }
};

module.exports = { requireAuth, checkUser };
