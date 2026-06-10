export function dbQuery(id: string, name: string) {
  // Vulnerable cross-file query
  db.query("SELECT * FROM users WHERE id = " + id);
}

export const dbDelete = (input: string) => {
  // Vulnerable NoSQL
  Model.find({ $where: input });
}
