import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import { DOMParser } from '@xmldom/xmldom';

export function handleRequest(req, res) {
  const userInput = req.query.input;

  // 1. SSRF Bypass (Request + URL)
  const myUrl = new URL(userInput);
  const myReq = new Request(myUrl);
  fetch(myReq);

  // 2. Command Injection Bypass (Obscure array joining)
  const args = [userInput];
  exec('echo ' + args.join(' '));

  // 3. SQLi Bypass (Tagged Templates or weird concatenations)
  const db = { query: (q) => {} };
  function sql(strings, ...values) { return strings[0] + values[0]; }
  db.query(sql`SELECT * FROM users WHERE id = ${userInput}`);

  // 4. XXE Bypass (setting weird properties)
  const parser = new DOMParser({
    locator: {},
    errorHandler: { warning: function (w) { } }
  });
  // If we don't set resolveEntity, it might be vulnerable, but maybe the rule only looks for a specific pattern.
  parser.parseFromString(userInput, "text/xml");

  // 5. Path Traversal Bypass
  const maliciousPath = path.join(process.cwd(), 'public', '..', '..', userInput);
  fs.readFileSync(maliciousPath);

  // 6. XSS Bypass
  const badHtml = ['<div', '>', userInput, '</div>'].join('');
  document.getElementById('app').innerHTML = badHtml;
}
