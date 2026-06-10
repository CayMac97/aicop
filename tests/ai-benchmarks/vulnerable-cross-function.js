const express = require('express');
const router = express.Router();
const db = require('db');

// Pattern 1: Helper function that builds SQL string
function buildQuery(userId) {
    return "SELECT * FROM users WHERE id = " + userId;
}

router.get('/user1', (req, res) => {
    // VULNERABLE: req.query.id is passed to buildQuery
    const query = buildQuery(req.query.id);
    db.query(query);
    res.send('ok');
});

// Pattern 2: Arrow function helper
const getCommandArgs = (host) => {
    return [host, '-t', '10'];
};

const { spawn } = require('child_process');

router.post('/ping', (req, res) => {
    // VULNERABLE: Array args with tainted value returned from helper
    const args = getCommandArgs(req.body.target);
    spawn('ping', args);
    res.send('ok');
});

// SAFE Pattern: validated input
function buildSafeQuery(id) {
    // ID is parsed to int, not a string concat of untrusted data
    const safeId = parseInt(id, 10);
    if (isNaN(safeId)) return null;
    return "SELECT * FROM users WHERE id = " + safeId;
}

router.get('/user2', (req, res) => {
    // SAFE
    const query = buildSafeQuery(req.query.id);
    if (query) {
        db.query(query);
    }
    res.send('ok');
});

module.exports = router;
