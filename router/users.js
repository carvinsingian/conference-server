const express = require('express');
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('config');
const atob = require("atob");
const User = require('../models/user');

const router = express.Router();


const checkToken = (req, res, next) => {
  const header = req.headers['authorization'];

  if (typeof header !== 'undefined') {
    const bearer = header.split(' ');
    const token = bearer[1];

    req.token = token;
    next();
  } else {
    //If header is undefined return Forbidden (403)
    res.sendStatus(403)
  }
}


const parseJwt = (token) => {
  try {
    return JSON.parse(atob(token.split('.')[1])).user;
  } catch (err) {
    return err.message;
  }
};


// @route     GET /api/user/all
// @desc      Get all user accounts
// @access    Public
router.get('/all', async (req, res) => {
  try {
    const users = await User.find()
    return res.json(users);
  } catch (err) {
    console.error(err.message);
    return res.status(500).send('Server error');
  }
})


// @route     GET /api/user/:username
// @desc      Get a user account by username
// @access    Public
router.get('/:username', async (req, res) => {
  try {
    const user = await User.findOne({ "username": req.params.username })

    if (user === null) {
      return res.status(404).json({ msg: "User not found" });
    }

    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
})


// @route     POST /api/user/signup
// @desc      Register a user
// @access    Public
router.post('/register',
  [
    check('username', 'Please add a username').not().isEmpty(),
    check('password', 'Please enter a password with 8 or more characters').isLength({ min: 8 })
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password, mobile_token } = req.body;

    const salt = await bcrypt.genSalt(10);
    console.log(salt);
    hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username: username,
      password: hashedPassword,
      mobile_token: mobile_token
    })

    try {
      //Check if the username is already existing
      const existingUser = await User.findOne({ "username": req.body.username });
      if (existingUser) {
        return res.status(400).json({ msg: "User already exists" });
      }

      const createdUser = await newUser.save();
      const payload = {
        user: createdUser
      }

      //creating jwt along with payload
      jwt.sign(
        payload,
        config.get('jwtSecret'),
        {
          expiresIn: 360000,
        },
        (err, token) => {
          if (err) throw err;
          return res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Server error');
    }
  })


// @route     PATCH /api/user/:username/update
// @desc      Update user details
// @access    Private
router.patch('/:username/update',
  checkToken,
  [
    check('password', 'Please enter a password with 8 or more characters').isLength({ min: 8 })
  ],
  async (req, res) => {
    jwt.verify(req.token, config.get('jwtSecret'), (err) => {
      if (err) {
        res.status(401).json({ msg: "Invalid token", error: err })
      }
    });

    const loggedInUser = (parseJwt(req.token));

    if (loggedInUser.username != req.params.username) {
      res.status(403).json({ msg: "Operation not allowed. Must be signed in as user" });
    }

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const requestBody = req.body;
      const existingUser = await User.findOne({ "username": req.params.username });

      if (existingUser === null) {
        return res.status(404).json({ msg: "User not found" });
      }

      for (const key in requestBody) {
        if (key === "password") {
          const newPassword = requestBody[key];
          const salt = await bcrypt.genSalt(10);
          hashedNewPassword = await bcrypt.hash(newPassword, salt);
          requestBody[key] = hashedNewPassword;
        }
        existingUser[key] = requestBody[key];
      }

      const updatedUser = await existingUser.save();
      return res.json(updatedUser);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Server error');
    }
  })


// @route     DELETE /api/user/:username/delete
// @desc      Delete a user
// @access    Private
router.delete('/:username/delete',
  checkToken,
  async (req, res) => {
    jwt.verify(req.token, config.get('jwtSecret'), (err) => {
      if (err) {
        res.status(401).json({ msg: "Invalid token", error: err })
      }
    });

    const loggedInUser = (parseJwt(req.token));

    if (loggedInUser.username != req.params.username) {
      res.status(403).json({ msg: "Operation not allowed. Must be signed in as user" });
    }

    try {
      const existingUser = await User.findOne({ "username": req.params.username });

      if (existingUser === null) {
        return res.status(404).json({ msg: "User not found" });
      }

      const deletedUser = await existingUser.delete();
      return res.json(deletedUser);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Server error');
    }
  })

module.exports = router;