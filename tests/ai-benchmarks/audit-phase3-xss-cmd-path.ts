// XSS
function xssVuln1(req: any, res: any) {
  res.send(`<h1>Hello ${req.query.name}</h1>`); // Should be detected
}
function xssVuln2(req: any, res: any) {
  const content = "<div>" + req.body.html + "</div>";
  res.write(content); // Should be detected
}
function xssSafe(req: any, res: any) {
  res.send(`<h1>Hello ${sanitizeHTML(req.query.name)}</h1>`); // Should NOT be detected
}
function xssEdge(req: any, res: any) {
  const { html } = req.body;
  res.send(`<div>${html ?? 'default'}</div>`); // Should be detected
}

// Command Injection
import { exec, spawn } from 'child_process';
function cmdVuln1(req: any, res: any) {
  exec(`ls -l ${req.query.dir}`); // Should be detected
}
function cmdSafe1(req: any, res: any) {
  spawn('ls', ['-l', req.query.dir]); // Should NOT be detected (spawn with args array is usually safe)
}
function cmdEdge(req: any, res: any) {
  const dir = req.body.dir || '/tmp';
  const command = ["ls", "-l", dir].join(" ");
  exec(command); // Should be detected
}

// Path Traversal
import fs from 'fs';
import path from 'path';
function pathVuln1(req: any, res: any) {
  let filePath = '/var/www/uploads/' + req.query.filename;
  fs.readFileSync(filePath); // Should be detected
}
function pathSafe1(req: any, res: any) {
  const filename = path.basename(req.query.filename);
  fs.readFileSync('/var/www/uploads/' + filename); // Should NOT be detected
}
function pathEdge(req: any, res: any) {
  const { filename } = req.query;
  const target = path.join('/var/www', filename);
  fs.readFile(target, (err, data) => {}); // Should be detected
}


 
