const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  mobile_token: {
    type: String,
    default: null,
  }
})

module.exports = mongoose.model('User', userSchema);