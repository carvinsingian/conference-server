const express = require('express');
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const config = require('config');
const atob = require("atob");
const ConferenceRoom = require('../models/conference_room');
const User = require('../models/user');
const { v4: uuidv4 } = require('uuid');

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


// @route     GET /api/room/:uuid
// @desc      get conference room details by uuid
// @access    Public
router.get('/:room_id', async (req, res) => {
  try {
    const conferenceRoom = await ConferenceRoom.findOne({ _id: req.params.room_id });

    if (conferenceRoom === null) {
      return res.status(404).json({ msg: "Room not found" });
    }

    res.json(conferenceRoom);
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
})


// @route     POST /api/room/create
// @desc      create conference room
// @access    Private
router.post('/create',
  checkToken,
  [
    check('room_name', 'Please add a room name').not().isEmpty(),
  ],
  async (req, res) => {
    jwt.verify(req.token, config.get('jwtSecret'), (err) => {
      if (err) {
        res.status(401).json({ msg: "Invalid token", error: err })
      }
    });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const loggedInUser = (parseJwt(req.token));

    const { room_name, capacity_limit } = req.body;

    const generatedId = uuidv4();

    const newConferenceRoom = new ConferenceRoom({
      _id: generatedId,
      room_name: room_name,
      host_user: loggedInUser.username,
      capacity_limit: capacity_limit
    })

    try {
      const createdConferenceRoom = await newConferenceRoom.save()
      return res.json(createdConferenceRoom);
    } catch (err) {
      console.error(err.message);
      return res.status(500).send('Server error');
    }
  })


// @route     PATCH /api/room/change_host
// @desc      change the host of a room
// @access    Private  
router.patch('/change_host',
  checkToken,
  [
    check('username', 'Please add a username').not().isEmpty(),
    check('room_id', 'Please add a room_id').not().isEmpty()
  ],
  async (req, res) => {
    jwt.verify(req.token, config.get('jwtSecret'), (err) => {
      if (err) {
        res.status(401).json({ msg: "Invalid token", error: err })
      }
    });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const loggedInUser = (parseJwt(req.token));

    try {
      const conferenceRoom = await ConferenceRoom.findOne({ _id: req.body.room_id });

      if (conferenceRoom === null) {
        return res.status(404).json({ msg: "Room not found" });
      }

      if (conferenceRoom.host_user != loggedInUser.username) {
        return res.status(403).json({ msg: "Operation not allowed. Must be signed in as host user" })
      }

      const newHostUser = await User.findOne({ username: req.body.username });

      if (newHostUser === null) {
        return res.status(404).json({ msg: "User not found" });
      }

      conferenceRoom.host_user = newHostUser.username;

      const updatedConferenceRoom = await conferenceRoom.save();
      return res.json(updatedConferenceRoom)
    } catch (err) {
      return res.status(500).send('Server error');
    }
  })


// @route     PATCH /api/room/join
// @desc      join a room
// @access    Private
router.patch('/join',
  checkToken,
  [
    check('room_id', 'Please add a room_id').not().isEmpty()
  ],
  async (req, res) => {
    jwt.verify(req.token, config.get('jwtSecret'), (err) => {
      if (err) {
        res.status(401).json({ msg: "Invalid token", error: err })
      }
    });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const loggedInUser = (parseJwt(req.token));

    try {
      const conferenceRoom = await ConferenceRoom.findOne({ _id: req.body.room_id });

      if (conferenceRoom === null) {
        return res.status(404).json({ msg: "Room not found" });
      }

      if (conferenceRoom.host_user === loggedInUser.username) {
        return res.status(403).json({ msg: "Operation not allowed. You are already the host of the room" })
      }

      if (!(conferenceRoom.participants.length < conferenceRoom.capacity_limit - 1)) {
        return res.status(403).json({ msg: "Operation not allowed. Room is already full" })
      }

      const index = conferenceRoom.participants.indexOf(loggedInUser.username);

      if (index >= 0) {
        return res.status(403).json({ msg: "User already in the room" })
      }

      conferenceRoom.participants.push(loggedInUser.username);
      const updatedConferenceRoom = await conferenceRoom.save();
      return res.json(updatedConferenceRoom);
    } catch (err) {
      return res.status(500).send('Server error')
    }

  }
)


// @route     PATCH /api/room/leave
// @desc      leave a room
// @access    Private
router.patch('/leave',
  checkToken,
  [
    check('room_id', 'Please add a room_id').not().isEmpty()
  ],
  async (req, res) => {
    jwt.verify(req.token, config.get('jwtSecret'), (err) => {
      if (err) {
        res.status(401).json({ msg: "Invalid token", error: err })
      }
    });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const loggedInUser = (parseJwt(req.token));

    try {
      const conferenceRoom = await ConferenceRoom.findOne({ _id: req.body.room_id });

      if (conferenceRoom === null) {
        return res.status(404).json({ msg: "Room not found" });
      }

      if (conferenceRoom.host_user === loggedInUser.username) {
        return res.status(403).json({ msg: "Operation not allowed. You are the host of the room" })
      }

      const index = conferenceRoom.participants.indexOf(loggedInUser.username);

      if (index >= 0) {
        conferenceRoom.participants.splice(index, 1);
      } else {
        return res.status(404).json({ msg: "User not in room" });
      }

      const updatedConferenceRoom = await conferenceRoom.save();

      return res.json(updatedConferenceRoom);
    } catch (err) {
      return res.status(500).send('Server error' + err.message);
    }

  }
)


// @route     GET /api/room/get/:username
// @desc      Get list of rooms the user is in
// @access    Public
router.get('/get/:username',
  async (req, res) => {
    try {
      const conferenceRooms = await ConferenceRoom.find();

      if (conferenceRooms.length === 0) {
        return res.status(404).json({ msg: "No rooms found. Create one first!" });
      }

      const activeRooms = [];

      for (const conferenceRoom of conferenceRooms) {
        if (conferenceRoom.host_user === req.params.username) {
          activeRooms.push(conferenceRoom.room_name);
        }

        const index = conferenceRoom.participants.indexOf(req.params.username);

        if (index > 0) {
          activeRooms.push(conferenceRoom.room_name);
        }
      }

      if (activeRooms.length === 0) {
        return res.json({ msg: "User has not joined any rooms" })
      }

      return res.json(activeRooms);
    } catch (err) {
      return res.status(500).send('Server error' + err.message);
    }

  }
)


module.exports = router;