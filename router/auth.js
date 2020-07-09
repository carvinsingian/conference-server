const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const config = require('config');
const User = require('../models/user');

const router = express.Router();


// @route     GET /api/auth
// @desc      Get logged in user
// @access    Private
router.get('/', async (req, res) => {
  res.send('Get logged in user');
});


// @route     POST /api/auth/login
// @desc      Auth user & get token
// @access    Public
router.post('/login',
  [
    check('username', 'Username is required').not().isEmpty(),
    check('password', 'Password is required').not().isEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body

    try {
      const user = await User.findOne({ username: username });

      if (!user) {
        res.status(401).json({ msg: 'Invalid Credentials' });
      }

      bcrypt.compare(password, user.password).then(result => {
        if (result === true) {
          const payload = {
            user: user
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
        }
        else {
          return res.status(401).json({ msg: 'Invalid Credentials' });
        }
      })
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  });


// @route     POST /api/auth/verify
// @desc      Verify user auth token
// @access    Private
router.post('/verify', async (req, res) => {
  jwt.verify(req.body.sessionToken, config.get('jwtSecret'), (err) => {
    if (err) {
      res.status(401).json({ msg: 'Invalid Token' });
    } else {
      res.status(200).json({ msg: "Token valid" });
    }
  })
});

module.exports = router;