import { bFunc } from './b';

function handleRequest(req: any) {
  bFunc(req.body.id);
}
