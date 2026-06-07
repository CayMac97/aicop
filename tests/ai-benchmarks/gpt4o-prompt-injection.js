const express = require('express');
const router = express.Router();
const openai = require('openai');
const anthropic = require('@anthropic-ai/sdk');
const { ChatOpenAI } = require('langchain/chat_models/openai');

// VULNERABLE: OpenAI
router.post('/chat', async (req, res) => {
    await openai.chat.completions.create({
        messages: [{ role: "user", content: req.body.message }]
    });
    res.send('ok');
});

// VULNERABLE: Anthropic
router.post('/anthropic', async (req, res) => {
    const prompt = req.query.prompt;
    await anthropic.messages.create({
        messages: [{ role: "user", content: prompt }]
    });
    res.send('ok');
});

// VULNERABLE: Langchain
router.post('/langchain', async (req, res) => {
    const chain = new ChatOpenAI();
    await chain.invoke({ input: req.body.userInput });
    res.send('ok');
});

// SAFE: Sanitized
router.post('/safe', async (req, res) => {
    const safeMsg = sanitize(req.body.message);
    await openai.chat.completions.create({
        messages: [{ role: "user", content: safeMsg }]
    });
    res.send('ok');
});

function sanitize(input) {
    return input.replace(/</g, "&lt;");
}

module.exports = router;
