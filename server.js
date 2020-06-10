const express = require('express');
const db = require('./knexConfig');
const sessions = require('express-session');
const bcrypt = require('bcrypt');

const server = express();

server.use(express.json());

server.use(sessions({
    name: 'supersecretsession',
    secret: 'I bet in a million years you cant guess this secret',
    cookie: {
        maxAge: 1 * 60 * 60 * 1000, // shoud be an hour,
        secure: false,
    },
    httpOnly: true,
    resave: false,
    saveUninitialized: false
}));


server.post('/api/register', (req, res) => {
    const newUser = req.body;
    if (newUser.username && newUser.password){
        // create the user in the database
        const hash = bcrypt.hashSync(newUser.password, 12);
        db('users')
            .insert({username: newUser.username, password: hash})
            .then(user => {
                res.json(201).json(user);
            })
            .catch(err => {
                res.json(500).json({errorMessage: `There was an internal server error when trying to save the credentials to the database: ${err}`});
            });
    } else {
        res.status(400).json({ errorMessage: "You did not provide valid credentials to register the user"})
    }
});

server.post('/api/login', (req, res) => {
    const user = req.body;
    if(user.username && user.password){
        // verify credentials and login
        db('users')
            .first()
            .where('username', user.username)
            .then(users => {
                if (users && bcrypt.compareSync(user.password, users.password)){
                    req.session.user = users;
                    res.status(200).json({message: `Welcome ${user.username}!`})
                } else {
                    res.status(401).json({errorMessage: "Invalid credentials"})
                }
            })
            .catch(err => {
                res.status(500).json({errorMessage: `There was an error with retrieving the data from the database ${err}`});
            });
    } else {
        res.status(400).json( {errorMessage: "please be sure to provide a password and a username to login "});
    }
});

server.get('/api/users', (req, res) => {
    if(req.session && req.session.user){
        db('users')
            .then(users => {
                res.status(200).json(users);
            })
            .catch(err => {
                res.status(500).json({ errorMessage: `There was an issue with getting the users from the database ${err}`})
            })
    } else {
        res.status(400).json( {errorMessage: "You shall not pass!"} );
    }
});


// Test stuff to make sure server was up and running
// server.get('/', (req, res) => {
//     res.status(200).json({successMessage: "the server has been set up correctly"});
// });

server.get('/api/test', (req, res) => {
    db('users')
        .then(users => {
            res.status(200).json(users);
        })
        .catch(err => {
            res.status(500).json({ errorMessage: `There was an internal server error with the request ${err}`})
        });
});

server.listen(5000, () => {
    console.log('Server listening on port 5000');
});