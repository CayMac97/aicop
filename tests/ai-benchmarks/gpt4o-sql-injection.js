const express = require('express');
const router = express.Router();
const db = require('../db'); // mock db
const pool = require('../db').pool; // mock pool

// VULNERABLE
router.get('/user1', (req, res) => {
    const userId = req.query.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query);
    res.send('ok');
});

// VULNERABLE
router.get('/user2', (req, res) => {
    db.query("SELECT * FROM users WHERE id = " + req.params.id);
    res.send('ok');
});

// VULNERABLE
router.post('/order', (req, res) => {
    db.query(`SELECT * FROM orders WHERE user = ${req.body.userId}`);
    res.send('ok');
});

// VULNERABLE
router.delete('/user', (req, res) => {
    const username = req.body.username;
    const sql = "DELETE FROM users WHERE name='" + username + "'";
    pool.execute(sql);
    res.send('ok');
});

// VULNERABLE
router.post('/log', (req, res) => {
    const input = req.body.data;
    pool.execute("INSERT INTO logs VALUES ('" + input + "')");
    res.send('ok');
});

// SAFE
router.get('/safe', (req, res) => {
    const userId = req.query.id;
    const query = "SELECT * FROM users WHERE id = ?";
    db.query(query, [userId]);
    res.send('ok');
});

module.exports = router;
