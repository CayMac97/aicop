import { dbQuery } from './index';

function handleRequest(req: any) {
  dbQuery(req.body.id);
}
