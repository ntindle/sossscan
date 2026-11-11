/**
 * A JSON Schema checker for the tests: enough of JSON Schema 2020-12 to check the API's schemas (lib/openapi.ts) and the
 * MCP server's (lib/mcp-tools.ts) against real answers.
 */
type Json = Record<string, any>;

/**
 * Where `value` breaks `schema`, as JSON Schema 2020-12 reads the keywords lib/openapi.ts uses. Any other keyword is a
 * break too, so none is skipped without notice. `strict`: an object may have only the properties its schema lists,
 * unless the schema says what else it may have. `seen` collects, for each schema, the properties values had.
 */
export function breaks(
  schema: Json,
  value: unknown,
  ctx: { doc: Json; strict: boolean; seen?: Map<Json, Set<string>> },
  at = '$',
): string[] {
  const known = ['description', 'examples', 'default', 'deprecated', 'title'].concat(
    ['$ref', 'type', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const', 'pattern'],
    ['minLength', 'maxLength', 'minimum', 'maximum', 'format', 'anyOf', 'not', 'propertyNames', 'minItems', 'maxItems'],
  );
  const out = Object.keys(schema)
    .filter((k) => !known.includes(k))
    .map((k) => `${at}: the schema has a keyword this check doesn't know, ${k}`);
  if (schema.$ref) return [...out, ...breaks(resolve(ctx.doc, schema.$ref), value, ctx, at)];
  const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);
  const types: string[] | null = schema.type === undefined ? null : [schema.type].flat();
  const is: Record<string, (v: unknown) => boolean> = {
    object: isObject,
    array: Array.isArray,
    string: (v) => typeof v === 'string',
    number: (v) => typeof v === 'number' && Number.isFinite(v),
    integer: Number.isInteger,
    boolean: (v) => typeof v === 'boolean',
    null: (v) => v === null,
  };
  if (types && !types.some((t) => is[t](value))) return [...out, `${at}: ${JSON.stringify(value)} isn't ${types}`];
  if ('const' in schema && value !== schema.const) out.push(`${at}: isn't ${schema.const}`);
  if (schema.enum && !schema.enum.includes(value)) out.push(`${at}: ${JSON.stringify(value)} isn't in the enum`);
  if (typeof value === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern, 'u').test(value)) out.push(`${at}: ${value} breaks the pattern`);
    if (value.length < (schema.minLength ?? 0) || value.length > (schema.maxLength ?? Infinity)) {
      out.push(`${at}: ${value} is the wrong length`);
    }
    if (schema.format === 'uri' && !URL.canParse(value)) out.push(`${at}: ${value} isn't a URI`);
    if (schema.format === 'date-time' && !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value)) {
      out.push(`${at}: ${value} isn't a date-time`);
    }
  }
  if (typeof value === 'number' && (value < (schema.minimum ?? -Infinity) || value > (schema.maximum ?? Infinity))) {
    out.push(`${at}: ${value} is out of range`);
  }
  if (schema.anyOf && !schema.anyOf.some((s: Json) => !breaks(s, value, ctx, at).length)) {
    out.push(`${at}: matches none of anyOf`);
  }
  if (schema.not && !breaks(schema.not, value, { ...ctx, seen: undefined }, at).length) out.push(`${at}: matches not`);
  if (Array.isArray(value) && schema.items)
    value.forEach((v, i) => out.push(...breaks(schema.items, v, ctx, `${at}[${i}]`)));
  if (Array.isArray(value) && (value.length < (schema.minItems ?? 0) || value.length > (schema.maxItems ?? Infinity))) {
    out.push(`${at}: has ${value.length} items`);
  }
  if (isObject(value)) {
    for (const key of schema.required ?? []) if (!(key in value)) out.push(`${at}: has no ${key}`);
    for (const [key, v] of Object.entries(value)) {
      if (schema.propertyNames) out.push(...breaks(schema.propertyNames, key, ctx, `${at} key ${key}`));
      if (schema.properties && key in schema.properties) {
        if (!ctx.seen?.has(schema)) ctx.seen?.set(schema, new Set());
        ctx.seen?.get(schema)!.add(key);
        out.push(...breaks(schema.properties[key], v, ctx, `${at}.${key}`));
      } else if (isObject(schema.additionalProperties)) {
        out.push(...breaks(schema.additionalProperties, v, ctx, `${at}.${key}`));
      } else if (schema.additionalProperties === false || (ctx.strict && schema.properties)) {
        out.push(`${at}: has ${key}, which the schema doesn't list`);
      }
    }
  }
  return out;
}

export function resolve(doc: Json, ref: string): Json {
  return ref
    .replace(/^#\//, '')
    .split('/')
    .reduce((node, part) => node[part.replaceAll('~1', '/').replaceAll('~0', '~')], doc);
}

/** Every schema with properties that `schema` uses, following $refs. */
export function objectSchemas(schema: unknown, doc: Json, found = new Set<Json>()): Set<Json> {
  if (!schema || typeof schema !== 'object' || found.has(schema as Json)) return found;
  const s = schema as Json;
  if (s.$ref) return objectSchemas(resolve(doc, s.$ref), doc, found);
  if (s.properties) found.add(s);
  for (const next of [...Object.values(s.properties ?? {}), s.items, s.additionalProperties, ...(s.anyOf ?? [])]) {
    objectSchemas(next, doc, found);
  }
  return found;
}
