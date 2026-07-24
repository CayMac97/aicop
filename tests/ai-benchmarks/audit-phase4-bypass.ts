import { exec } from 'child_process';
import db from 'db';

// 1. Indirect calls (Wrapper function)
function runCmd(cmd) {
  exec(cmd); // The taint engine needs to track inter-procedural flow here
}
function bypass1(req: any, res: any) {
  runCmd(req.body.cmd);
}

// 2. Computed Properties
function bypass2(req: any, res: any) {
  const method = 'que' + 'ry';
  db[method](`SELECT * FROM users WHERE id = ${req.body.id}`); 
}

// 3. String concatenation via Array joining (obfuscation)
function bypass3(req: any, res: any) {
  const parts = ["SELECT * FROM users WHERE id =", req.body.id];
  const query = parts.join(" ");
  db.query(query);
}

// 4. Object.assign taint loss
function bypass4(req: any, res: any) {
  const input = {};
  Object.assign(input, req.body);
  db.query(`SELECT * FROM users WHERE id = ${input.id}`);
}
