/**
 * Data file: maps object/module names to lists of methods that do NOT exist
 * on those objects — common hallucinations produced by AI code generators.
 */
export interface HallucinatedApiEntry {
  objectName: string;
  methods: string[];
  realAlternative: string;
}

export const HALLUCINATED_APIS: HallucinatedApiEntry[] = [
  {
    objectName: 'req',
    methods: ['getBody', 'getParams', 'getQuery', 'getHeader', 'getCookies', 'getSession', 'getUser', 'getData'],
    realAlternative: 'Use req.body, req.params, req.query, req.headers, req.cookies, req.session directly',
  },
  {
    objectName: 'res',
    methods: ['sendJSON', 'sendError', 'sendHTML', 'sendOK', 'returnJson', 'sendSuccess'],
    realAlternative: 'Use res.json(), res.status(code).json(), res.send(), res.render()',
  },
  {
    objectName: 'app',
    methods: ['useMiddleware', 'addRoute', 'configure', 'registerMiddleware', 'addMiddleware'],
    realAlternative: 'Use app.use(), app.get(), app.post(), app.put(), app.delete()',
  },
  {
    objectName: 'fs',
    methods: ['readFileToString', 'writeText', 'readAllFiles', 'writeJSON', 'readJSON', 'readDir', 'copyDir'],
    realAlternative: 'Use fs.readFileSync(), fs.writeFileSync(), fs.readdirSync() or fs-extra equivalents',
  },
  {
    objectName: 'fetch',
    methods: ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'],
    realAlternative: 'fetch() is a function, not an object. Use fetch(url, { method: "POST", ... })',
  },
  {
    objectName: 'mongoose',
    methods: ['findByIdAndDeleteAll', 'findAllById', 'createOrUpdate', 'findOrCreate', 'upsert'],
    realAlternative: 'Use Model.findByIdAndDelete(), Model.findById(), Model.findOneAndUpdate({ upsert: true })',
  },
  {
    objectName: 'Schema',
    methods: ['addField', 'removeField', 'addMethod', 'registerPlugin'],
    realAlternative: 'Define schema fields in the constructor. Use schema.add(), schema.methods, schema.plugin()',
  },
  {
    objectName: 'router',
    methods: ['addRoute', 'registerRoute', 'addMiddleware'],
    realAlternative: 'Use router.get(), router.post(), router.use()',
  },
  {
    objectName: 'console',
    methods: ['print', 'println', 'verbose', 'fatal', 'success'],
    realAlternative: 'Use console.log(), console.error(), console.warn(), console.info(), console.debug()',
  },  {
    objectName: 'arr',
    methods: ['flatten', 'contains', 'append', 'insert'],
    realAlternative: 'arr.flatten() → arr.flat() | arr.contains() → arr.includes() | arr.append() → arr.push() | arr.insert() does not exist',
  },
  {
    objectName: 'str',
    methods: ['capitalize', 'contains', 'reverse', 'truncate'],
    realAlternative: 'capitalize/reverse/truncate do not exist in JS | str.contains() → str.includes()',
  },];

/** Lookup map for fast access: objectName -> { method -> realAlternative } */
export const HALLUCINATED_API_MAP: Map<string, Map<string, string>> = new Map(
  HALLUCINATED_APIS.map((entry) => [
    entry.objectName,
    new Map(entry.methods.map((m) => [m, entry.realAlternative])),
  ]),
);
