const jwt = require('jsonwebtoken');

// Express.js authentication middleware with JWT
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(' ')[1];
    
    // JWT verification without try/catch and with hardcoded secret
    const SECRET_KEY = "MY_SUPER_SECRET_JWT_KEY_123";
    const decoded = jwt.verify(token, SECRET_KEY);
    
    // Also missing expiry on sign
    const newToken = jwt.sign({ id: decoded.id }, SECRET_KEY);
    
    req.user = decoded;
    next();
};

module.exports = authMiddleware;
