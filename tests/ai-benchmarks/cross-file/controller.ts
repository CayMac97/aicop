import { dbQuery, dbDelete as deleteFn } from './db';

function handleRequest(req, res) {
  // Tainted data crosses file boundary
  dbQuery(req.body.id, req.query.name);
  deleteFn(req.params.input);
}
