const express = require('express');
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const { ensureLoggedIn } = require('../middleware/auth');
const Message = require('../models/message');

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get('/:id', ensureLoggedIn, async (req, res, next) => {
    try {
        let username = req.user.username;
        const message = await Message.get(req.params.id);
        if (message.from_user.username === username || message.to_user.username === username){ 
            return res.json({ message })           
        } else {
            throw new ExpressError('Unauthorized request', 401)
        }
    } catch(e) {
        next(e)
    }
})

/** POST / - post message.
 *
 * {to_username, body} =>      (Needs "_token" in body as well)
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post('/', ensureLoggedIn, async (req, res, next) => {
    try {
        const message = await Message.create({
            from_username: req.body.from_username,
            to_username: req.body.to_username,
            body: req.body.body
        });
        return res.json({ message })
    } catch(e) {
        next(e)
    }
})

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
router.post('/:id/read', ensureLoggedIn, async (req, res, next) => {
    try {
        const recipient = await Message.get(req.params.id);
        if (recipient.to_user.username === req.user.username) {
            const message = await Message.markRead(req.params.id);
            return res.json({ message })
        } else {
            throw new ExpressError('Unauthorized request', 401)
        }
    } catch(e) {
        next(e)
    }
})

module.exports = router;