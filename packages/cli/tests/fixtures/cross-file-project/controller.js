import { handleUserModification } from './services/user-service.js';

export function setupRoutes(app) {
  app.post('/users', (req, res) => {
    // Vulnerable source
    const userId = req.body.id;
    const userData = req.body.data;
    
    handleUserModification(userId, userData);
    
    res.send('Done');
  });
}
