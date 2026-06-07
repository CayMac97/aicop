const express = require('express');
const router = express.Router();
const db = require('../db');
const Model = require('../models/User');
const mongoose = require('mongoose');

// 1. Direkt
router.post('/direct', (req, res) => {
    db.collection('users').find({ name: req.body.username });
    res.send('ok');
});

// 2. Via Variable
router.post('/variable', (req, res) => {
    const filter = { name: req.body.username };
    db.collection('users').find(filter);
    res.send('ok');
});

// 3. Via Variable + $where
router.post('/where-var', (req, res) => {
    const query = { $where: req.body.condition };
    Model.find(query);
    res.send('ok');
});

// 4. Direkt + $where
router.post('/where-direct', (req, res) => {
    Model.find({ $where: req.body.input });
    res.send('ok');
});

// 5. Safe: ObjectId cast
router.get('/safe', (req, res) => {
    const id = new mongoose.Types.ObjectId(req.params.id);
    Model.findById(id);
    res.send('ok');
});

module.exports = router;
