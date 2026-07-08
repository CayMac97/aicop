import { db } from '../db/db-utils.js';

export function handleUserModification(id, data) {
  // Vulnerable sink across multiple files
  const query = "UPDATE users SET data='" + data + "' WHERE id=" + id;
  db.exec(query);
}
