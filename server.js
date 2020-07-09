const express = require('express');
const mongoose = require('mongoose');

//setting up express
const server = express();
const port = 5000;

//creating database connection
const url = 'mongodb://localhost/ConferenceDB';
mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true });
const con = mongoose.connection;

con.on('open', () => console.log('database connected...'));

server.get('/', (req, res) => {
  res.json({ message: "Conference Room APIs" })
})

//setting express to take set json as request format
server.use(express.json());
server.use('/api/user', require('./router/users'));
server.use('/api/auth', require('./router/auth'));
server.use('/api/room', require('./router/conference_room'));

server.listen(port, () => console.log(`Server is running on port ${port}`));