export function dbQuery(id: string) {
  return "SELECT * FROM users WHERE id = " + id;
}
