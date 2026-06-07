const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();

// REST endpoint for file upload/download
router.get('/download', (req, res) => {
    // Missing try/catch or file existence check
    // Direct path traversal vulnerability
    const data = fs.readFileSync(req.query.file);
    
    res.send(data);
});

module.exports = router;
