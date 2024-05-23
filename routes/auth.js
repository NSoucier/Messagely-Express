const express = require('express');
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const { SECRET_KEY } = require('../config');

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
          throw new ExpressError("Username and password required", 400);
        }
        if (await User.authenticate(username, password)) {
            await User.updateLoginTimestamp(username);
            const token = jwt.sign({ username }, SECRET_KEY);
            return res.json({ token })
        } else {
            throw new ExpressError('Invalid username/password', 400)
        }
    } catch(e) {
        next(e)
    }
})

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post('/register', async (req, res, next) => {
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        if (!username || !password || !first_name || !last_name || !phone) {
            throw new ExpressError("Username, password, phone, first and last name are required", 400);
        }
        let user = await User.register(req.body);    
        const token = jwt.sign({ username }, SECRET_KEY);
        await User.updateLoginTimestamp(user.username);
        return res.json({ token })
    } catch(e) {
        next(e)
    }

}) 

module.exports = router;
