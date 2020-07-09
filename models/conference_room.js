const mongoose = require('mongoose');

const conferenceRoomSchema = new mongoose.Schema({
  _id: {
    type: String,
    required: true
  },
  room_name: {
    type: String,
    required: true
  },
  host_user: {
    type: String,
    required: true
  },
  participants: {
    type: Array,
  },
  capacity_limit: {
    type: Number,
    default: 5,
  }
})

module.exports = mongoose.model('ConferenceRoom', conferenceRoomSchema);