// XXE
import libxmljs from 'libxmljs';
function xxeVuln(req: any) {
  const xml = req.body.xml;
  libxmljs.parseXmlString(xml, { noent: true }); // Should be detected
}
function xxeSafe(req: any) {
  libxmljs.parseXmlString(req.body.xml, { noent: false }); // Safe
}
function xxeEdge(req: any) {
  const options = { noent: true, ...req.body.opts };
  libxmljs.parseXmlString(req.body.xml, options); // Edge
}

// SSRF
import axios from 'axios';
function ssrfVuln(req: any) {
  axios.get(req.query.url); // Should be detected
}
function ssrfSafe(req: any) {
  const allowed = ["https://api.github.com"];
  if (allowed.includes(req.query.url)) {
    axios.get(req.query.url); // Safe
  }
}
function ssrfEdge(req: any) {
  const { url = 'http://localhost' } = req.body;
  axios.post(url, {}); // Should be detected
}

// Insecure Deserialization
import serialize from 'node-serialize';
function desVuln(req: any) {
  serialize.unserialize(req.cookies.data); // Should be detected
}

// Hardcoded Secrets
function secretsVuln() {
  const apiKey = "sk_dummy_1234567890abcdef1234567890abcdef"; // Should be detected
  return apiKey;
}

// Prototype Pollution
function protoVuln(req: any) {
  const obj = {};
  const { path, value } = req.body;
  obj[path] = value; // Potential PP
}

// ReDoS
function redosVuln(req: any) {
  const regex = new RegExp(req.body.regex); // Should be detected
  regex.test("some string");
}
function redosVuln2() {
  const re = /(a+)+b/; // Should be detected
}

// Insecure Randomness
function randomVuln() {
  return Math.random(); // Should be detected (in crypto contexts, though we can't tell context, usually flagged as warn)
}
