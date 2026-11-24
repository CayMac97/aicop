import { describe, it, expect } from 'vitest';
// Load the rule index first (as the app does): some rules import the cross-file resolver,
// which imports scan-file -> rules/index (import cycle if a rule is loaded before the index).
import '../src/scanner/rules/index.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse } from '@typescript-eslint/typescript-estree';
import nPlusOne from '../src/scanner/rules/tech-debt/n-plus-one-queries.js';
import regexDos from '../src/scanner/rules/security/regex-dos.js';
import hallucinated from '../src/scanner/rules/ai-smells/hallucinated-api-calls.js';
import nosql from '../src/scanner/rules/security/nosql-injection.js';
import deserialization from '../src/scanner/rules/security/insecure-deserialization.js';
import magicNumbers from '../src/scanner/rules/ai-smells/magic-numbers.js';
import pathTraversal from '../src/scanner/rules/security/path-traversal.js';
import xss from '../src/scanner/rules/security/xss-vulnerabilities.js';
import regexDosRule from '../src/scanner/rules/security/regex-dos.js';
import xxeRule from '../src/scanner/rules/security/xxe-injection.js';
import openRedirect from '../src/scanner/rules/security/open-redirect.js';
import insecureSession from '../src/scanner/rules/security/insecure-session.js';
import weakCrypto from '../src/scanner/rules/security/weak-crypto.js';
import sqlInjectionRule from '../src/scanner/rules/security/sql-injection.js';
import ssrfRisk from '../src/scanner/rules/security/ssrf-risk.js';
import commandInjection from '../src/scanner/rules/security/command-injection.js';
import evalUsage from '../src/scanner/rules/security/eval-usage.js';
import unsafeShell from '../src/scanner/rules/security/unsafe-shell-execs.js';
import missingTypes from '../src/scanner/rules/tech-debt/missing-types.js';
import mixedAsync from '../src/scanner/rules/ai-smells/mixed-async-patterns.js';
import type { Rule } from '../src/scanner/rules/types.js';

function run(rule: Rule, code: string, file = 'src/file.ts', jsx = false) {
  const ast = parse(code, { loc: true, range: true, comment: true, jsx }) as any;
  return rule.check(ast, code, file);
}

describe('n-plus-one-queries (found on express / vercel-commerce / juice-shop)', () => {
  it('does not treat code AFTER a loop as being inside the loop', () => {
    const code = `
      for (const x of xs) { total += x; }
      request(app).delete('/');
      db.users.find({ id: 1 });
    `;
    expect(run(nPlusOne, code)).toHaveLength(0);
  });

  it('still flags awaited DB calls inside a loop', () => {
    const code = `
      async function f(ids) {
        for (const id of ids) {
          await User.findOne({ where: { id } });
        }
      }
    `;
    expect(run(nPlusOne, code)).toHaveLength(1);
  });

  it('still flags a write on a DB-like receiver inside a loop', () => {
    const code = `
      for (const r of rows) { ordersCollection.insert({ r }); }
    `;
    expect(run(nPlusOne, code)).toHaveLength(1);
  });

  it('ignores bare helper calls such as updateImage() in a map callback', () => {
    const code = `
      items.map((item) => updateImage(item.id));
    `;
    expect(run(nPlusOne, code)).toHaveLength(0);
  });

  it('ignores .update() on hashes / signals and DOM querySelector', () => {
    const code = `
      for (const f of files) {
        const h = crypto.createHash('md5').update(f).digest('hex');
        this.messages.update((prev) => prev);
        document.querySelector('#x');
      }
    `;
    expect(run(nPlusOne, code)).toHaveLength(0);
  });
});

describe('regex-dos nested quantifier detection', () => {
  it.each([
    ['/^\\/(.*)\\.(.*)/', 0],
    ['/.*\\/(.*)\\..*/', 0],
    ['/(.*)\\.(.*)/', 0],
    ['/(?<major>\\d+).(?<minor>\\d+)/', 0],
    ['/<(?:\\w+)\\W+?[\\w]/gi', 0],
    ['/(?:ab)+/', 0],
    ['/[(a+)+]/', 0],
    ['/(a+)+$/', 1],
    ['/(\\w+\\s?)*$/', 1],
    ['/([a-z]+)*x/', 1],
    ['/(?:a*)+b/', 1],
    ['/((a+)b)+/', 1],
  ])('%s -> %i finding(s)', (literal, expected) => {
    expect(run(regexDos, `const r = ${literal};`)).toHaveLength(expected as number);
  });
});

describe('hallucinated-api-calls: res is only Express when it follows req', () => {
  it('does not flag res.body on a custom fetch result', () => {
    const code = `
      async function getMenu() {
        const res = await shopifyFetch({ query });
        return res.body?.data?.menu?.items.map((i) => i.title);
      }
    `;
    expect(run(hallucinated, code)).toHaveLength(0);
  });

  it('still flags res.body.* inside an Express handler', () => {
    const code = `
      app.get('/x', (req, res) => {
        res.body.items.map((i) => i);
      });
    `;
    expect(run(hallucinated, code)).toHaveLength(1);
  });
});

describe('nosql-injection: dynamic $where without req.* (DAO layer)', () => {
  it('flags $where built from a raw parameter', () => {
    const code = `
      function find(userId, threshold) {
        const uid = parseInt(userId);
        return col.find({ $where: \`this.userId == \${uid} && this.stocks > '\${threshold}'\` });
      }
    `;
    expect(run(nosql, code)).toHaveLength(1);
  });

  it('does not flag $where when every interpolated value is numeric', () => {
    const code = `
      function find(userId, threshold) {
        const uid = parseInt(userId);
        const t = Number(threshold);
        return col.find({ $where: \`this.userId == \${uid} && this.stocks > \${t}\` });
      }
    `;
    expect(run(nosql, code)).toHaveLength(0);
  });

  it('does not flag a constant $where string', () => {
    expect(run(nosql, `col.find({ $where: 'this.a == this.b' });`)).toHaveLength(0);
  });

  it('reports a req-tainted $where only once', () => {
    const code = `
      app.get('/r', (req, res) => {
        db.reviews.find({ $where: 'this.product == ' + req.params.id });
      });
    `;
    expect(run(nosql, code)).toHaveLength(1);
  });
});

describe('insecure-deserialization: js-yaml version awareness', () => {
  function project(version: string | null) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aicop-yaml-'));
    if (version) {
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { 'js-yaml': version } }));
    }
    return path.join(dir, 'app.ts');
  }
  const code = `import yaml from 'js-yaml';\nconst c = yaml.load(readInput());`;

  it('flags yaml.load of user input on js-yaml 3 as error', () => {
    const c = `import yaml from 'js-yaml';\napp.post('/y', (req, res) => { yaml.load(req.body.doc); });`;
    const findings = run(deserialization, c, project('^3.14.0'));
    expect(findings.some((f) => f.severity === 'error')).toBe(true);
  });

  it('flags yaml.load of other dynamic data on js-yaml 3 only as warn', () => {
    const findings = run(deserialization, code, project('^3.14.0'));
    expect(findings.some((f) => f.severity === 'warn')).toBe(true);
    expect(findings.some((f) => f.severity === 'error')).toBe(false);
  });

  it('recognises js-yaml under any local name (jsYaml.load) and respects safe schemas', () => {
    const base = `const jsYaml = require('js-yaml');\napp.post('/y', (req, res) => { `;
    const v3 = project('^3.14.0');
    expect(run(deserialization, base + `jsYaml.load(req.body.doc); });`, v3).some((f) => f.severity === 'error')).toBe(true);
    expect(run(deserialization, base + `jsYaml.load(req.body.doc, { schema: jsYaml.JSON_SCHEMA }); });`, v3)
      .filter((f) => f.severity !== 'info')).toHaveLength(0);
  });

  it('does not flag yaml.load or the import on js-yaml 4', () => {
    expect(run(deserialization, code, project('^4.1.0'))).toHaveLength(0);
  });

  it('does not warn when only safeLoad is imported', () => {
    const findings = run(deserialization, `import { safeLoad } from 'js-yaml';`, project(null));
    expect(findings).toHaveLength(0);
  });

  it('only notes (info) a plain js-yaml import with unknown version', () => {
    const findings = run(deserialization, `import yaml from 'js-yaml';`, project(null));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('info');
  });
});

describe('magic-numbers', () => {
  it('ignores hex bit masks', () => {
    expect(run(magicNumbers, `ctx.stencilFunc(ctx.EQUAL, 1, 0xffffffff);`)).toHaveLength(0);
  });

  it('still flags large decimal literals', () => {
    expect(run(magicNumbers, `const t = compute(86400000);`).length).toBeGreaterThan(0);
  });
});

describe('mixed-async-patterns: framework-contract callbacks', () => {
  it('ignores async inline handlers in JSX attributes', () => {
    const code = `const A = () => <form action={async () => { doThing(); }} />;`;
    expect(run(mixedAsync, code, 'a.tsx', true)).toHaveLength(0);
  });

  it('ignores async functions used as object property values', () => {
    const code = `export const t = tool({ execute: async ({ n }) => { const c = make(n); log(c); log(c); } });`;
    expect(run(mixedAsync, code)).toHaveLength(0);
  });

  it('still flags async declarations that never await', () => {
    const code = `async function prepare() { const a = compute(); log(a); store(a); }`;
    expect(run(mixedAsync, code)).toHaveLength(1);
  });
});

describe('unsafe-shell-execs: only real child_process calls', () => {
  it('ignores RegExp.prototype.exec()', () => {
    const code = `
      const keyValuePairsReg = /a=(b)/g;
      let matches = keyValuePairsReg.exec(paramsList);
      while ((match = regex.exec(content)) !== null) { links.push(match[1]); }
      const m = PORT_REGEX.exec(this.host);
    `;
    expect(run(unsafeShell, code)).toHaveLength(0);
  });

  it('still flags child_process.exec with dynamic input (require namespace)', () => {
    const code = `const cp = require('child_process'); cp.exec('ls ' + dir);`;
    expect(run(unsafeShell, code)).toHaveLength(1);
  });

  it('still flags destructured exec (require and import), also inside functions', () => {
    expect(run(unsafeShell, `const { exec } = require('child_process'); exec(cmd);`)).toHaveLength(1);
    expect(run(unsafeShell, `import { exec as run } from 'node:child_process'; run(cmd);`)).toHaveLength(1);
    expect(run(unsafeShell, `function f(cmd) { const { execSync } = require('child_process'); return execSync(cmd); }`)).toHaveLength(1);
  });

  it('still flags { shell: true }', () => {
    expect(run(unsafeShell, `spawn(cmd, args, { shell: true });`)).toHaveLength(1);
  });

  it('does not flag a bare exec() that is not from child_process', () => {
    expect(run(unsafeShell, `function exec(x) { return x; } exec(input);`)).toHaveLength(0);
  });
});

describe('missing-types: contextually typed functions', () => {
  it('does not require parameter types when the variable has a type annotation', () => {
    const code = `const h: Handler = function (request, reply) { return reply; };`;
    expect(run(missingTypes, code)).toHaveLength(0);
  });

  it('still flags untyped parameters on plain functions', () => {
    const code = `function add(a, b) { return a + b; }`;
    expect(run(missingTypes, code).length).toBeGreaterThan(0);
  });
});

describe('hallucinated-api-calls: built-in bound names', () => {
  it('does not flag params.get() when params is a URLSearchParams', () => {
    const code = `
      function f() {
        const params = new URLSearchParams(window.location.search);
        return params.get('query');
      }
    `;
    expect(run(hallucinated, code)).toHaveLength(0);
  });
});

describe('xss-vulnerabilities: res.send / res.write (rule used to crash on every res.send)', () => {
  it('flags reflected XSS: res.send(req.query.name + html)', () => {
    const code = `app.get('/hi', (req, res) => { res.send('<h1>' + req.query.name + '</h1>'); });`;
    const findings = run(xss, code);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].ruleId).toBe('security/xss-vulnerabilities');
  });

  it('still analyses the rest of the file when a res.send() has no argument', () => {
    const code = `
      app.get('/a', (req, res) => { res.send(); });
      app.get('/b', (req, res) => { res.send('<p>' + req.query.q + '</p>'); });
    `;
    expect(run(xss, code).length).toBeGreaterThan(0);
  });

  it('does not flag dynamic non-user data when no HTML content type is set', () => {
    const code = `
      function sendChunk(payload, res) { res.write(payload); }
      app.get('/x', (req, res) => { res.send(buildData()); });
    `;
    expect(run(xss, code)).toHaveLength(0);
  });

  it('flags dynamic content when the file serves text/html', () => {
    const code = `
      app.get('/p', (req, res) => {
        res.setHeader('Content-Type', 'text/html');
        res.send(renderPage());
      });
    `;
    expect(run(xss, code).length).toBeGreaterThan(0);
  });
});

describe('path-traversal: containment guards', () => {
  it('flags fs.readFile with a user-controlled path', () => {
    const code = `app.get('/f', (req, res) => { fs.readFile('./files/' + req.query.name, (e, d) => res.send(d)); });`;
    expect(run(pathTraversal, code).length).toBeGreaterThan(0);
  });

  it('does not flag when an early-exit startsWith() guard precedes the sink', () => {
    const code = `
      app.use('/infra', (req, res, next) => {
        const filePath = path.resolve('infra', path.normalize(req.path));
        if (!filePath.startsWith(path.resolve('infra'))) {
          return res.status(403).end();
        }
        fs.readFile(filePath, 'utf8', (err, data) => res.send(data));
      });
    `;
    expect(run(pathTraversal, code)).toHaveLength(0);
  });

  it('does not flag path.resolve(user) when a startsWith() early-exit guard follows', () => {
    const code = `
      app.use((req, res, next) => {
        const p = path.resolve('base', req.path);
        if (!p.startsWith(path.resolve('base'))) { return res.status(403).end(); }
        res.sendStatus(200);
      });
    `;
    expect(run(pathTraversal, code)).toHaveLength(0);
  });

  it('still flags path.resolve(user) without any guard', () => {
    const code = `app.get('/f', (req, res) => { const p = path.resolve('base', req.query.f); doSomething(p); });`;
    expect(run(pathTraversal, code).length).toBeGreaterThan(0);
  });

  it('a startsWith() condition without early exit is not treated as a guard', () => {
    const code = `
      app.get('/f', (req, res) => {
        const p = path.resolve('base', req.query.f);
        if (!p.startsWith('base')) { console.log('suspicious'); }
        fs.readFile(p, (e, d) => res.send(d));
      });
    `;
    expect(run(pathTraversal, code).length).toBeGreaterThan(0);
  });
});

describe('taint guard recognition does not hang on empty derivations', () => {
  it('terminates for arrays filled by push() and joined (const collected = [])', () => {
    const code = `
      async function f(req, res) {
        const userInput = req.body?.payload || "";
        const collected = [];
        collected.push(userInput);
        const data = collected.join(',');
        if (!/^(asc)$/.test(String(data))) { return; }
      }
    `;
    expect(() => run(regexDosRule, code)).not.toThrow();
  });
});

describe('validation guard: comparing another property of req is not validation', () => {
  it('keeps flagging libxmljs noent with req.files data despite a mimetype check', () => {
    const code = `
      const libxmljs = require('libxmljs');
      app.post('/x', (req, res) => {
        if (req.files.products && req.files.products.mimetype == 'text/xml') {
          libxmljs.parseXmlString(req.files.products.data.toString('utf8'), { noent: true });
        }
      });
    `;
    const f = run(xxeRule, code);
    expect(f.some((x) => x.severity === 'error')).toBe(true);
  });

  it('still treats an allowlist check on the SAME request value as validation', () => {
    const code = `
      const allowed = new Set(['a.txt']);
      app.get('/f', (req, res) => {
        if (!allowed.has(req.query.name)) { return res.sendStatus(403); }
        fs.readFile('/data/' + req.query.name, (e, d) => res.send(d));
      });
    `;
    expect(run(pathTraversal, code)).toHaveLength(0);
  });
});

describe('path-traversal: concatenation heuristics', () => {
  it('ignores URL building and object property values', () => {
    const code = `
      const out = { imageUrl: req.protocol + '://' + req.get('host') + '/' + m.image,
                    imagePath: 'assets/uploads/' + req.file.filename };
    `;
    expect(run(pathTraversal, code)).toHaveLength(0);
  });
});

describe('taint: ternary with allowlist test', () => {
  it('treats `allowed.includes(x) ? x : "default"` as validated, but still taints `cond ? x : y`', () => {
    const safe = `app.get('/a', (req, res) => { const e = ['jpg','png'].includes(req.query.ext) ? req.query.ext : 'jpg'; fs.readFile('/img/a.' + e, cb); });`;
    expect(run(pathTraversal, safe)).toHaveLength(0);
    const unsafe = `app.get('/a', (req, res) => { const e = req.query.flag ? req.query.ext : 'jpg'; fs.readFile('/img/a.' + e, cb); });`;
    expect(run(pathTraversal, unsafe).length).toBeGreaterThan(0);
  });
});

describe('taint transport patterns', () => {
  const cp = `const childProcess = require("child_process");\n`;
  it('follows an expression-bodied helper: const trim = v => String(v).trim()', () => {
    const code = cp + `async function h(req, res) { const input = req.cookies.t || ""; const trim = (v) => String(v).trim(); const data = trim(input); childProcess.execSync("echo " + data); }`;
    expect(run(unsafeShell, code).some((f) => f.severity === 'error')).toBe(true);
  });
  it('follows a returned closure: capture(v) => () => v', () => {
    const code = cp + `async function h(req, res) { const input = req.headers["user-agent"] || ""; const capture = (v) => () => String(v).trim(); const read = capture(input); const data = read(); childProcess.exec("echo " + data); }`;
    expect(run(unsafeShell, code).some((f) => f.severity === 'error')).toBe(true);
  });
  it('follows an object getter and util.format', () => {
    const g = cp + `async function h(req, res) { const input = req.headers.referer || ""; const p = { get value() { return input; } }; const data = p.value; childProcess.exec("echo " + data); }`;
    expect(run(unsafeShell, g).some((f) => f.severity === 'error')).toBe(true);
    const u = cp + `const nodeUtil = require("util");\nasync function h(req, res) { const data = nodeUtil.format("%s", req.query.x); childProcess.exec("echo " + data); }`;
    expect(run(unsafeShell, u).some((f) => f.severity === 'error')).toBe(true);
  });
  it('does not treat a helper that ignores its argument as a taint carrier', () => {
    const code = cp + `async function h(req, res) { const input = req.query.x || ""; const label = (v) => "const"; const data = label(input); childProcess.exec("echo " + data); }`;
    expect(run(unsafeShell, code).some((f) => f.severity === 'error')).toBe(false);
  });
  it('does not attribute a callback return to the outer function', () => {
    const code = cp + `async function h(req, res) { const input = req.query.x || ""; const f = (v) => { [1,2].map((n) => { return v; }); return "ok"; }; const data = f(input); childProcess.exec("echo " + data); }`;
    expect(run(unsafeShell, code).some((f) => f.severity === 'error')).toBe(false);
  });
});

describe('open-redirect: header and framework variants', () => {
  it.each([
    ['res.location()', `app.get('/r', (req, res) => { res.location(String(req.query.next)).sendStatus(303); });`],
    ['status().set("Location")', `app.get('/r', (req, res) => { return res.status(302).set("Location", String(req.query.next)).end(); });`],
    ['setHeader("Location")', `app.get('/r', (req, res) => { res.setHeader("Location", req.query.next); res.statusCode = 302; res.end(); });`],
    ['writeHead(303, {Location})', `app.get('/r', (req, res) => { res.writeHead(303, { Location: req.query.next }).end(); });`],
    ['koa ctx.redirect', `router.get('/r', async (ctx) => { ctx.redirect(ctx.query.next); });`],
  ])('flags %s', (_n, code) => {
    expect(run(openRedirect, code).length).toBeGreaterThan(0);
  });

  it('does not flag a fixed-origin prefix or an allowlisted target', () => {
    expect(run(openRedirect, `app.get('/r', (req, res) => { res.redirect('/home?next=' + req.query.next); });`)).toHaveLength(0);
    const guarded = `
      const ALLOWED = new Set(['/a', '/b']);
      app.get('/r', (req, res) => {
        const next = String(req.query.next);
        if (!ALLOWED.has(next)) { return res.sendStatus(400); }
        res.status(302).set("Location", next).end();
      });`;
    expect(run(openRedirect, guarded)).toHaveLength(0);
  });
});

describe('xss: res.end html, Koa ctx.body, unescaped template placeholders', () => {
  it('flags res.end with an HTML string, but not a plain-text res.end', () => {
    expect(run(xss, `app.get('/a', (req, res) => { res.end("<section>" + req.query.q + "</section>"); });`).length).toBeGreaterThan(0);
    expect(run(xss, `app.get('/a', (req, res) => { res.end("ok " + req.query.q); });`)).toHaveLength(0);
  });
  it('flags Koa ctx.body HTML built from input, not from constants', () => {
    expect(run(xss, `router.get('/a', async (ctx) => { ctx.body = "<h1>" + ctx.query.name + "</h1>"; });`).length).toBeGreaterThan(0);
    expect(run(xss, `router.get('/a', async (ctx) => { ctx.body = "<h1>Hello</h1>"; });`)).toHaveLength(0);
  });
  it('flags `| safe` placeholders fed with input and ignores escaped ones', () => {
    const bad = `app.get('/a', (req, res) => { res.send(nunjucks.renderString('<div>{{ bio | safe }}</div>', { bio: req.body.bio })); });`;
    const ok = `app.get('/a', (req, res) => { res.send(nunjucks.renderString('<div>{{ bio }}</div>', { bio: req.body.bio })); });`;
    expect(run(xss, bad).length).toBeGreaterThan(0);
    expect(run(xss, ok)).toHaveLength(0);
  });
});

describe('insecure-session: sensitive cookies without Secure', () => {
  it.each([
    ['res.cookie without secure', `app.get('/', (req, res) => { res.cookie("session", "x", { httpOnly: true, sameSite: "strict" }); });`],
    ['res.cookie secure:false', `app.get('/', (req, res) => { res.cookie("auth_token", "x", { secure: false }); });`],
    ['Set-Cookie header', `app.get('/', (req, res) => { res.setHeader("Set-Cookie", "session=" + encodeURIComponent(v) + "; Path=/; HttpOnly"); });`],
    ['stringifySetCookie', `app.get('/', (req, res) => { res.append("Set-Cookie", stringifySetCookie({ name: "session", value: v, httpOnly: true })); });`],
    ['koa ctx.cookies.set', `router.get('/', async (ctx) => { ctx.cookies.set("session", "x", { httpOnly: true }); });`],
  ])('flags %s', (_n, code) => {
    expect(run(insecureSession, code).length).toBeGreaterThan(0);
  });

  it.each([
    ['secure:true', `app.get('/', (req, res) => { res.cookie("session", "x", { secure: true, httpOnly: true }); });`],
    ['secure from config', `app.get('/', (req, res) => { res.cookie("session", "x", { secure: isProd }); });`],
    ['Secure in header', `app.get('/', (req, res) => { res.setHeader("Set-Cookie", "session=" + v + "; Path=/; Secure; HttpOnly"); });`],
    ['non-sensitive cookie', `app.get('/', (req, res) => { res.cookie("theme", "dark"); });`],
    ['stringifySetCookie secure', `app.get('/', (req, res) => { res.append("Set-Cookie", stringifySetCookie({ name: "session", value: v, secure: true })); });`],
  ])('does not flag %s', (_n, code) => {
    expect(run(insecureSession, code)).toHaveLength(0);
  });
});

describe('weak-crypto: ECB mode, createCipher, subtle.digest', () => {
  it('flags ECB mode and legacy createCipher; not GCM', () => {
    expect(run(weakCrypto, `crypto.createCipheriv("aes-256-ecb", key, null);`).length).toBeGreaterThan(0);
    expect(run(weakCrypto, `crypto.createCipheriv("aes-256-gcm", key, iv);`)).toHaveLength(0);
  });
  it('flags subtle.digest("SHA-1") but not SHA-256', () => {
    expect(run(weakCrypto, `const d = await crypto.subtle.digest("SHA-1", buf);`).length).toBeGreaterThan(0);
    expect(run(weakCrypto, `const d = await crypto.subtle.digest("SHA-256", buf);`)).toHaveLength(0);
  });
});

describe('sql-injection: raw-only SQL APIs', () => {
  it.each([
    ['sequelize.literal', `app.get('/a', async (req, res) => { await User.findAll({ where: sequelize.literal("name = '" + req.query.n + "'") }); });`],
    ['prisma $queryRawUnsafe', `app.get('/a', async (req, res) => { await prisma.$queryRawUnsafe("SELECT * FROM u WHERE id = '" + req.query.id + "'"); });`],
    ['knex whereRaw', `app.get('/a', async (req, res) => { await knex('u').whereRaw("name = '" + req.query.n + "'"); });`],
  ])('flags %s', (_n, code) => {
    expect(run(sqlInjectionRule, code).length).toBeGreaterThan(0);
  });
  it('does not flag literal() with a constant', () => {
    expect(run(sqlInjectionRule, `await User.findAll({ where: sequelize.literal("deleted_at IS NULL") });`)).toHaveLength(0);
  });
});

describe('ssrf-risk: sockets, dns and request config objects', () => {
  it.each([
    ['net.connect to a parsed host', `app.get('/a', (req, res) => { net.connect(80, new URL(String(req.query.u)).hostname); });`],
    ['dns.lookup', `app.get('/a', (req, res) => { dns.lookup(req.query.host, cb); });`],
    ['axios config object', `app.get('/a', async (req, res) => { await axios.request({ method: 'get', url: String(req.query.u) }); });`],
    ['config via local variable', `app.get('/a', async (req, res) => { const cfg = { url: req.query.u, timeout: 5 }; await axios(cfg); });`],
  ])('flags %s', (_n, code) => {
    expect(run(ssrfRisk, code).length).toBeGreaterThan(0);
  });
  it('ignores constant targets and an allowlisted host', () => {
    expect(run(ssrfRisk, `net.connect(80, 'internal.example.com');`)).toHaveLength(0);
    expect(run(ssrfRisk, `app.get('/a', async (req, res) => { await axios.request({ url: 'https://api.example.com/x', params: { q: req.query.q } }); });`)).toHaveLength(0);
  });
});

describe('ssrf-risk: member-expression URL arguments (rule used to throw ReferenceError)', () => {
  it('flags axios.get(req.query.url) and does not crash', () => {
    const f = run(ssrfRisk, `app.get('/p', async (req, res) => { const r = await axios.get(req.query.url); res.send(r.data); });`);
    expect(f.length).toBeGreaterThan(0);
  });
});

describe('command-injection: argument arrays without a shell', () => {
  const cp = `const childProcess = require("child_process");\n`;
  it('does not flag execFile("echo", [tainted]) (no shell)', () => {
    expect(run(commandInjection, cp + `app.get('/a', (req, res) => { childProcess.execFileSync("echo", [req.query.x]); });`)).toHaveLength(0);
  });
  it('still flags spawn with shell:true or a shell binary', () => {
    expect(run(commandInjection, cp + `app.get('/a', (req, res) => { childProcess.spawn("echo", [req.query.x], { shell: true }); });`).length).toBeGreaterThan(0);
    expect(run(commandInjection, cp + `app.get('/a', (req, res) => { childProcess.spawn("sh", ["-c", req.query.x]); });`).length).toBeGreaterThan(0);
  });
  it('still flags a tainted command itself', () => {
    expect(run(commandInjection, cp + `app.get('/a', (req, res) => { childProcess.exec("ls " + req.query.dir); });`).length).toBeGreaterThan(0);
  });
});

describe('validated taint is neutralised (eval / shell)', () => {
  it('eval of an allowlist-validated value is not reported, eval of raw input still is', () => {
    const ok = `app.get('/a', (req, res) => { const d = String(req.query.m); if (!/^(asc|desc)$/.test(d)) { return res.sendStatus(400); } eval(d); });`;
    expect(run(evalUsage, ok)).toHaveLength(0);
    const bad = `app.get('/a', (req, res) => { eval(req.query.m); });`;
    expect(run(evalUsage, bad).some((f) => f.severity === 'error')).toBe(true);
  });
});

describe('taint: escaping idioms', () => {
  it('html-escape replace chains and SQL identifier quoting sanitise', () => {
    const html = `app.get('/a', (req, res) => { const e = String(req.query.q).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;"); res.send("<p>" + e + "</p>"); });`;
    expect(run(xss, html)).toHaveLength(0);
    const sqlq = `app.get('/a', async (req, res) => { const col = '"' + String(req.query.c).replace(/"/g, '""') + '"'; await db.query("SELECT id FROM t ORDER BY " + col); });`;
    expect(run(sqlInjectionRule, sqlq)).toHaveLength(0);
  });
  it('a partial escape (only <) does not sanitise', () => {
    const partial = `app.get('/a', (req, res) => { const e = String(req.query.q).replace(/</g,"&lt;"); res.send("<p>" + e + "</p>"); });`;
    expect(run(xss, partial).length).toBeGreaterThan(0);
  });
});
