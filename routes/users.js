const express = require("express");
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

// User model
const User = require('../Models/User')


//Login Page
router.get('/login', (req, res) => res.render('login'));

//Registe Page
router.get('/register', (req, res) => res.render('register'));

//Register Handle
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // check required fields
    if(!name || !email || !password || !password2) {
        errors.push({msg: 'Please fill in all fields'});
    }
    
    // check password match
    if(password !== password2) {
        errors.push({msg: 'Passwords do not match'});
    }

    // check password length
    if(password.length < 6) {
        errors.push({msg: 'Password should be greater than 6 characters'});
    }
    
    // re render

    if(errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // Validation passed
        // Find existing user
        User.findOne({ email: email })
            .then(user => {
                if(user) {
                    errors.push({msg: 'Email is already registered.'})
                    res.render('register', {
                        //user exists
                        errors,
                        name,
                        email,
                        password,
                        password2
                    });
                } else {
                    const newUser = new User({
                        name,
                        email,
                        password
                    });

                    // hash password
                    bcrypt.genSalt(10, (err, salt) => 
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if(err) throw err;
                            // Set password to hashed
                            newUser.password = hash;
                            // Save user
                            newUser.save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registered and can log in.')
                                    res.redirect('/users/login')
                                })
                                .catch(err => console.log(err))
                    }))
                    
                }
            })
    }
});

// Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next)
})

// Logout handle 
router.get('./logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are now logged out.');
    res.redirect('/login');
})


module.exports = router;