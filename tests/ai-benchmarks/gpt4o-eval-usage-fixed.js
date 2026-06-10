const express = require('express');
const router = express.Router();

router.post('/timer', (req, res) => {
    // VULNERABLE: setTimeout with tainted string via variable
    const userCode = req.body.script;
    setTimeout(userCode, 1000);

    // VULNERABLE: setInterval with direct tainted string
    setInterval(req.body.script, 500);

    res.send('ok');
});

router.post('/safe', (req, res) => {
    // SAFE: setTimeout with function reference
    const cb = () => console.log('done');
    setTimeout(cb, 1000);
    res.send('ok');
});

module.exports = router;
