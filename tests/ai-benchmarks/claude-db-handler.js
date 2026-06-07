const express = require('express');
const router = express.Router();
const User = require('../models/User');

// MongoDB query handler for a user service
router.get('/user', async (req, res) => {
    const { username } = req.query;
    
    // Direct usage of req.query.username in DB query (NoSQL injection risk)
    // Also missing null check on the result
    const user = await User.findOne({ username: username });
    
    res.json({
        id: user._id,
        name: user.name,
        email: user.email
    });
});

module.exports = router;
