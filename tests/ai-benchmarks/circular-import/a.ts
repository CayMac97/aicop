import { bFunc } from './b';

export function aFunc(id: string) {
  bFunc(id);
  return "SELECT * FROM A WHERE id = " + id;
}
