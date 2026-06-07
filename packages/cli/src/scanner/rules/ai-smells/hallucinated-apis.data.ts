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
    methods: ['readFileToString', 'writeText', 'readAllFiles', 'writeJSON', 'readJSON', 'readDir', 'copyDir', 'readFileAsync', 'writeFileAsync', 'existsAsync', 'mkdirAsync'],
    realAlternative: 'Use fs.readFileSync()/fs.promises.readFile() or fs-extra equivalents',
  },
  {
    objectName: 'prisma',
    methods: ['findAllWhere', 'findManyWhere', 'updateMany', 'upsertMany', 'deleteMany', 'findFirst'],
    realAlternative: 'Use prisma.model.findMany({ where: {} }) and ensure findFirst is properly parameterized',
  },
  {
    objectName: 'z',
    methods: ['validate', 'check', 'assert'],
    realAlternative: 'Use z.string().parse(x), z.string().safeParse(x), schema.parse(x)',
  },
  {
    objectName: 'params',
    methods: ['get', 'query', 'searchParams'],
    realAlternative: 'In Next.js App Router, use params.id directly. .get() is for searchParams.',
  },
  {
    objectName: 'searchParams',
    methods: ['query', 'getAll'],
    realAlternative: 'Use searchParams.get("key") or searchParams["key"]',
  },
  {
    objectName: 'db',
    methods: ['findMany', 'findOne'],
    realAlternative: 'In Drizzle ORM, use db.select().from(table).where(...) or db.query.table.findMany()',
  },
  {
    objectName: 'expect(...)',
    methods: ['toHaveBeenCalledOnce', 'toStrictDeepEqual', 'toMatchSnapshot.inline'],
    realAlternative: 'Use .toHaveBeenCalledTimes(1), .toStrictEqual(), .toMatchInlineSnapshot()',
  },
  {
    objectName: 'fetch',
    methods: ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'create'],
    realAlternative: 'fetch() is a function, not an object. Use fetch(url, { method: "POST", ... })',
  },
  {
    objectName: 'Model',
    methods: ['findAllById', 'updateById', 'deleteById', 'patch'],
    realAlternative: 'Use Model.findByIdAndUpdate, Model.findByIdAndDelete',
  },
  {
    objectName: 'mongoose',
    methods: ['findByIdAndDeleteAll', 'findAllById', 'createOrUpdate', 'findOrCreate', 'upsert'],
    realAlternative: 'Use Model.findByIdAndDelete(), Model.findById(), Model.findOneAndUpdate({ upsert: true })',
  },
  {
    objectName: 'Schema',
    methods: ['addField', 'removeField', 'addMethod', 'registerPlugin', 'findAll', 'find', 'findOne', 'create'],
    realAlternative: 'Schema is not a Model — define fields in the constructor, use schema.add()/schema.methods/schema.plugin(). Query methods belong on Model instances.',
  },
  {
    objectName: 'path',
    methods: ['resolve_sync', 'join_sync', 'exists', 'readFile', 'writeFile'],
    realAlternative: 'path.join() already runs synchronously and returns a string — no .sync variant exists. Use fs.existsSync() for file existence checks.',
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
  },
];

/** Lookup map for fast access: objectName -> { method -> realAlternative } */
export const HALLUCINATED_API_MAP: Map<string, Map<string, string>> = new Map(
  HALLUCINATED_APIS.map((entry) => [
    entry.objectName,
    new Map(entry.methods.map((m) => [m, entry.realAlternative])),
  ]),
);

/**
 * Two-level chain hallucinations: root.firstProp is invalid on the given root object.
 * Format: rootObject -> { firstPropName -> alternative message }
 * Used to flag patterns like app.express.routes.findOne() where .express doesn't exist on app.
 */
export const HALLUCINATED_CHAIN_MAP: Map<string, Map<string, string>> = new Map([
  ['app', new Map([
    ['express', 'app.express does not exist — app IS the Express instance; use app.get(), app.use(), app.listen() directly'],
    ['routes', 'app.routes.* does not exist — use express.Router() for sub-routers and app.use("/path", router)'],
  ])],
  ['res', new Map([
    ['query', 'res.query does not exist — query parameters are on req.query, not res.query'],
    ['params', 'res.params does not exist — use req.params instead'],
    ['body', 'res.body does not exist — the request body is on req.body'],
  ])],
]);
