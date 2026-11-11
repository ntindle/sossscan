/**
 * The API's description in OpenAPI 3.1 (https://spec.openapis.org/oas/v3.1.1), served at /openapi.json
 * (app/openapi.json/route.ts). It covers the public endpoints: the two scans and the health check. The GitHub App's
 * endpoints under /api/app/ are left out: they need a signed-in browser and a header only the site's page sends, and
 * some of them change a repository's settings or open pull requests.
 *
 * Each schema is plain JSON Schema (2020-12, the dialect OpenAPI 3.1 uses) and complete in itself: a schema that uses
 * another holds that object, not a reference. Other code can take one as it is, such as REPORT_SCHEMA as a tool's
 * output schema. openApiDocument() names them under components and turns each use into a $ref.
 *
 * Patterns, limits, error codes and examples come from the code that enforces or sends them, and tests/api.test.ts
 * checks the schemas against real reports and real error answers.
 */
import pkg from '../package.json';
import { ERROR_CODES, type ErrorCode, errorBody, field, HttpError, internalError } from './http.ts';
import { allowance, rateLimitError } from './limits.ts';
import { SITE } from './pages.ts';
import {
  invalidRepo,
  MAX_SCANS,
  NAME_MAX,
  NAME_RE,
  noResults,
  NOT_FOUND,
  OWNER_MAX,
  OWNER_RE,
  REPO_INPUT_RE,
  REPO_LENGTH,
  SCAN_CACHE_CONTROL,
  SCAN_TTL,
  scannerBusy,
} from './public-scan.ts';
import { ECOSYSTEM_FILES, RATE_LIMITED, SCHEMA, TIERS, VERSION } from './scanner/index.ts';

type Json = Record<string, unknown>;

/** The error codes the public API sends: the first group in ERROR_CODES. */
export const PUBLIC_ERROR_CODES: readonly ErrorCode[] = [
  'invalid_request',
  'invalid_repo',
  'not_found',
  'method_not_allowed',
  'repo_not_found',
  'scan_failed',
  'rate_limited',
  'internal_error',
  'scanner_busy',
];

/** The statuses a result can have, in the order a report's summary lists them. */
export const STATUSES = ['pass', 'warn', 'fail', 'info', 'unknown', 'na'] as const;

const HOURS = SCAN_TTL / 3600;

// ------------------------------------------------------------------------------------------- the report
const checkId = (description: string): Json => ({
  type: 'string',
  pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$',
  description,
  examples: ['ci-pin-actions'],
});

export const STATUS_SCHEMA: Json = {
  type: 'string',
  enum: [...STATUSES],
  description: [
    "A check's result:",
    '',
    '- `pass`: the control is in place.',
    "- `warn`: it's partly in place.",
    "- `fail`: it's missing.",
    '- `info`: a fact worth knowing, with no verdict.',
    "- `unknown`: this scan couldn't settle it: it needs admin access, or the scan couldn't read something.",
    "- `na`: it doesn't apply to this repository.",
  ].join('\n'),
};

export const EVIDENCE_SCHEMA: Json = {
  type: 'object',
  required: ['label', 'url'],
  properties: {
    label: { type: 'string', description: 'What the link points to, such as a file name.' },
    url: { type: 'string', format: 'uri', description: 'The link.' },
  },
  description: 'A link to what a result is based on.',
};

export const RESULT_SCHEMA: Json = {
  type: 'object',
  required: ['status', 'summary', 'evidence', 'details', 'layer'],
  properties: {
    status: STATUS_SCHEMA,
    summary: { type: 'string', description: 'What the scan saw, in one sentence.', examples: ['SECURITY.md found'] },
    evidence: { type: 'array', items: EVIDENCE_SCHEMA, description: 'Links to what the result is based on.' },
    details: {
      type: 'object',
      additionalProperties: true,
      description: "Facts that belong to this check, such as a file's path and length. Often empty.",
      examples: [{ path: 'SECURITY.md', length: 1293 }],
    },
    layer: {
      type: 'string',
      enum: ['public', 'private'],
      description: '`public` for a check anyone can read; `private` for one only a token with admin access can.',
    },
  },
  description: "One check's result.",
};

export const FINDING_SCHEMA: Json = {
  type: 'object',
  required: ['item_id', 'severity', 'title', 'path', 'line', 'url', 'hint'],
  properties: {
    item_id: checkId('The check it belongs to: a key of `results`.'),
    severity: {
      type: 'string',
      enum: ['high', 'medium', 'low'],
      description: 'How bad it is. The site fixes a check with a `high` finding first, then one with a `medium` one.',
    },
    title: { type: 'string', description: "What's wrong, in one line." },
    path: { type: ['string', 'null'], description: 'The file, or null.' },
    line: { type: ['integer', 'null'], minimum: 1, description: 'The line in that file, or null.' },
    url: { type: ['string', 'null'], format: 'uri', description: 'A link to the file and line on GitHub, or null.' },
    hint: { type: ['string', 'null'], description: 'How to fix it, in one line, or null.' },
  },
  description: 'A specific problem, such as an unpinned action, with the file and line when there is one.',
  examples: [
    {
      item_id: 'ci-persist-credentials',
      severity: 'low',
      title: 'actions/checkout keeps the token in .git/config',
      path: '.github/workflows/ci.yml',
      line: 12,
      url: 'https://github.com/owner/repo/blob/main/.github/workflows/ci.yml#L12',
      hint: 'Add "with: persist-credentials: false"',
    },
  ],
};

export const SCORECARD_SCHEMA: Json = {
  type: 'object',
  required: ['score', 'date', 'checks', 'reasons'],
  properties: {
    score: { type: ['number', 'null'], minimum: 0, maximum: 10, description: 'The overall score, from 0 to 10.' },
    date: {
      type: 'string',
      description: "When Scorecard scored the repository, as YYYY-MM-DD, or an empty string when it doesn't say.",
      examples: ['2026-11-09'],
    },
    checks: {
      type: 'object',
      additionalProperties: { type: ['number', 'null'], minimum: -1, maximum: 10 },
      description: "Each Scorecard check's score, from 0 to 10, or -1 when it couldn't be scored.",
      examples: [{ 'Code-Review': 7, Packaging: -1 }],
    },
    reasons: {
      type: 'object',
      additionalProperties: { type: ['string', 'null'] },
      description: "Scorecard's reason for each check's score.",
    },
  },
  description: "The repository's OpenSSF Scorecard result (https://scorecard.dev).",
};

export const TIER_SCHEMA: Json = {
  type: 'object',
  required: ['id', 'name'],
  properties: {
    id: { type: 'integer', minimum: TIERS[0].id, maximum: TIERS.at(-1)!.id },
    name: { type: 'string', enum: TIERS.map((t) => t.name) },
  },
  description: `The repository's size tier: the higher of its stars tier and its dependents tier. Tiers run from ${TIERS[0].id}, "${TIERS[0].name}", to ${TIERS.at(-1)!.id}, "${TIERS.at(-1)!.name}".`,
  examples: [{ id: TIERS[0].id, name: TIERS[0].name }],
};

export const SUMMARY_SCHEMA: Json = {
  type: 'object',
  required: [...STATUSES],
  properties: Object.fromEntries(STATUSES.map((s) => [s, { type: 'integer', minimum: 0 }])),
  description: 'How many checks got each status.',
};

const count = (description: string): Json => ({ type: 'integer', minimum: 0, description });

export const REPO_META_SCHEMA: Json = {
  type: 'object',
  required: [
    'stars',
    'forks',
    'watchers',
    'dependents',
    'dependents_total',
    'language',
    'topics',
    'default_branch',
    'archived',
    'private',
    'owner_type',
    'created_at',
    'description',
    'ecosystems',
    'workflow_count',
    'publishes_from_ci',
    'html_url',
    'has_security_tab',
    'admin_token',
  ],
  properties: {
    stars: count('Stars on GitHub.'),
    forks: count('Forks on GitHub.'),
    watchers: { type: ['integer', 'null'], minimum: 0, description: 'People watching the repository, or null.' },
    dependents: {
      type: ['object', 'null'],
      required: ['repositories', 'packages'],
      properties: { repositories: count('Repositories.'), packages: count('Packages.') },
      description: "What depends on it, from GitHub's dependency graph, or null when GitHub doesn't show it.",
    },
    dependents_total: {
      type: ['integer', 'null'],
      minimum: 0,
      description: 'Dependent repositories and packages together, or null.',
    },
    language: { type: ['string', 'null'], description: "The repository's main language, as GitHub detects it." },
    topics: { type: 'array', items: { type: 'string' }, description: "The repository's topics on GitHub." },
    default_branch: { type: 'string', examples: ['main'] },
    archived: { type: ['boolean', 'null'] },
    private: { type: 'boolean', description: 'Always false from this API, which scans public repositories only.' },
    owner_type: { type: 'string', description: 'What kind of account owns it.', examples: ['User', 'Organization'] },
    created_at: { type: ['string', 'null'], format: 'date-time', description: 'When the repository was created.' },
    description: { type: ['string', 'null'], description: "The repository's description on GitHub." },
    ecosystems: {
      type: 'array',
      items: { type: 'string', enum: [...new Set(ECOSYSTEM_FILES.map(([, ecosystem]) => ecosystem))] },
      description: 'The package ecosystems whose manifests the repository has.',
    },
    workflow_count: count('How many workflow files in .github/workflows the scan read.'),
    publishes_from_ci: { type: 'boolean', description: 'Whether a workflow publishes a package or a release.' },
    html_url: { type: ['string', 'null'], format: 'uri', description: "The repository's page on GitHub." },
    has_security_tab: { type: 'boolean', const: true, description: 'Always true.' },
    admin_token: {
      type: 'boolean',
      description: "Whether the scan's token had admin access, which the private checks need. Always false here.",
    },
    open_dependabot_alerts: {
      type: 'object',
      required: ['total', 'critical_high'],
      properties: { total: count('Open alerts.'), critical_high: count('Open alerts that are critical or high.') },
      description: 'Private scans only: open Dependabot alerts.',
    },
    allowed_actions: {
      type: ['string', 'null'],
      description: 'Private scans only: which actions the repository allows (`all`, `local_only` or `selected`).',
    },
  },
  description: 'Facts about the repository, from GitHub.',
};

export const REPORT_SCHEMA: Json = {
  type: 'object',
  required: [
    'schema',
    'tool',
    'repo',
    'scanned_at',
    'layer',
    'meta',
    'results',
    'findings',
    'errors',
    'scorecard',
    'tier',
    'summary',
    'api_calls',
    'cached',
  ],
  properties: {
    schema: { type: 'string', const: SCHEMA, description: `The report's format: always \`${SCHEMA}\`.` },
    tool: {
      type: 'object',
      required: ['name', 'version'],
      properties: {
        name: { type: 'string', const: 'sosf-scan' },
        version: { type: 'string', description: "The scanner's version.", examples: [VERSION] },
      },
      description: 'The scanner that wrote the report.',
    },
    repo: {
      type: 'string',
      pattern: `${OWNER_RE.source.slice(0, -1)}/${NAME_RE.source.slice(1)}`,
      description: 'The repository as OWNER/NAME, spelled the way GitHub spells it.',
      examples: ['ntindle/sossscan'],
    },
    scanned_at: {
      type: 'string',
      format: 'date-time',
      description: 'When the scan ran, in UTC.',
      examples: ['2026-11-11T03:51:49Z'],
    },
    layer: {
      type: 'string',
      enum: ['public', 'private', 'app'],
      description:
        "Which scan made it: `public` from this API, `private` from the CLI with an admin's token, `app` from a deep scan, which the site runs through its GitHub App.",
    },
    meta: REPO_META_SCHEMA,
    results: {
      type: 'object',
      propertyNames: checkId("A check's id."),
      additionalProperties: RESULT_SCHEMA,
      description: `One result per check, keyed by the check's id. Each check's steps, tier, impact and effort are in ${SITE}/data/guide.json, under \`items\`, with the same id.`,
    },
    findings: { type: 'array', items: FINDING_SCHEMA, description: 'Specific problems, with the file and line.' },
    errors: {
      type: 'array',
      items: { type: 'string' },
      description: "What got in the scan's way, such as a file it couldn't read or GitHub's rate limit. Usually empty.",
    },
    scorecard: {
      anyOf: [SCORECARD_SCHEMA, { type: 'null' }],
      description: "The repository's OpenSSF Scorecard result, or null when Scorecard has none.",
    },
    tier: TIER_SCHEMA,
    summary: SUMMARY_SCHEMA,
    api_calls: count('How many requests the scan made.'),
    cached: {
      type: 'boolean',
      description: `true when the server answered from its cache of the last ${HOURS} hours instead of scanning.`,
    },
  },
  description: `What a scan found, in the format \`${SCHEMA}\`: a result for each check, specific problems, and facts about the repository. The CLI writes the same report, without \`cached\`.`,
};

// --------------------------------------------------------------------------------------------- the rest
export const ERROR_CODE_SCHEMA: Json = {
  type: 'string',
  enum: [...PUBLIC_ERROR_CODES],
  description: [
    'What went wrong. A code keeps its meaning; a new kind of error gets a new code.',
    '',
    ...PUBLIC_ERROR_CODES.map((code) => `- \`${code}\`: ${ERROR_CODES[code]}`),
  ].join('\n'),
};

export const ERROR_SCHEMA: Json = {
  type: 'object',
  required: ['error', 'detail'],
  properties: {
    error: {
      type: 'object',
      required: ['code', 'message', 'hint'],
      properties: {
        code: ERROR_CODE_SCHEMA,
        message: { type: 'string', description: 'What went wrong. The words may change; the code does not.' },
        hint: { type: 'string', description: 'What to do next.' },
      },
    },
    detail: {
      type: 'string',
      deprecated: true,
      description: 'The same text as `error.message`, for clients written before the `error` object.',
    },
  },
  description:
    'Every error the API sends, whatever its status: a code for programs, and a message and a hint for people. Errors are sent with `Cache-Control: no-store`.',
};

export const SCAN_REQUEST_SCHEMA: Json = {
  type: 'object',
  required: ['repo'],
  properties: {
    repo: {
      type: 'string',
      minLength: REPO_LENGTH.min,
      maxLength: REPO_LENGTH.max,
      pattern: REPO_INPUT_RE.source,
      description:
        'The repository: OWNER/REPO, or its github.com URL. A URL may end in .git or go to a page in the repository.',
      examples: ['ntindle/sossscan', 'https://github.com/ntindle/sossscan'],
    },
    refresh: {
      type: 'boolean',
      default: false,
      description: `true skips the server's cache and scans again. Without it, a scan from the last ${HOURS} hours is reused.`,
    },
  },
  description: 'The repository to scan.',
};

export const HEALTH_SCHEMA: Json = {
  type: 'object',
  required: ['ok', 'scanner_version'],
  properties: {
    ok: { type: 'boolean', const: true, description: 'Always true.' },
    scanner_version: {
      type: 'string',
      description: "The scanner's version, the same as a report's `tool.version`.",
      examples: [VERSION],
    },
  },
  description: 'The server is up.',
};

/** The schemas by name, as components.schemas lists them. */
export const SCHEMAS: Record<string, Json> = {
  Report: REPORT_SCHEMA,
  RepoMeta: REPO_META_SCHEMA,
  Result: RESULT_SCHEMA,
  Status: STATUS_SCHEMA,
  Evidence: EVIDENCE_SCHEMA,
  Finding: FINDING_SCHEMA,
  Scorecard: SCORECARD_SCHEMA,
  Tier: TIER_SCHEMA,
  Summary: SUMMARY_SCHEMA,
  ScanRequest: SCAN_REQUEST_SCHEMA,
  Health: HEALTH_SCHEMA,
  Error: ERROR_SCHEMA,
  ErrorCode: ERROR_CODE_SCHEMA,
};

// -------------------------------------------------------------------------------------------- examples
/** A real report of this project's repository, trimmed to three of its results. */
const EXAMPLE_REPORT = {
  schema: SCHEMA,
  tool: { name: 'sosf-scan', version: VERSION },
  repo: 'ntindle/sossscan',
  scanned_at: '2026-11-11T03:51:49Z',
  layer: 'public',
  meta: {
    stars: 0,
    forks: 0,
    watchers: 0,
    dependents: { repositories: 0, packages: 0 },
    dependents_total: 0,
    language: 'TypeScript',
    topics: ['github-actions', 'nextjs', 'open-source', 'openssf', 'security', 'supply-chain-security'],
    default_branch: 'main',
    archived: false,
    private: false,
    owner_type: 'User',
    created_at: '2026-11-09T20:49:11Z',
    description:
      'Security scanner and guide for open source maintainers, built from what GitHub Secure Open Source Fund projects changed.',
    ecosystems: ['npm'],
    workflow_count: 4,
    publishes_from_ci: false,
    html_url: 'https://github.com/ntindle/sossscan',
    has_security_tab: true,
    admin_token: false,
  },
  results: {
    'disc-security-md': {
      status: 'pass',
      summary: 'SECURITY.md found',
      evidence: [{ label: 'SECURITY.md', url: 'https://github.com/ntindle/sossscan/blob/main/SECURITY.md' }],
      details: { path: 'SECURITY.md', length: 1293 },
      layer: 'public',
    },
    'plan-irp': {
      status: 'fail',
      summary: 'No incident response plan found in the repo',
      evidence: [],
      details: {},
      layer: 'public',
    },
    'secrets-push-protection': {
      status: 'unknown',
      summary: 'Push protection status needs the private scan',
      evidence: [],
      details: {},
      layer: 'public',
    },
  },
  findings: [],
  errors: [],
  scorecard: null,
  tier: { id: 0, name: 'Just you' },
  summary: { pass: 17, warn: 0, fail: 5, info: 7, unknown: 9, na: 6 },
  api_calls: 22,
  cached: false,
};

/** The error a call throws, for an example of it. */
function thrown(call: () => unknown): HttpError {
  try {
    call();
  } catch (e) {
    if (e instanceof HttpError) return e;
    throw e;
  }
  throw new Error('expected an HttpError');
}

/** Error examples, each the body the code sends for it. */
function errorExamples(examples: Record<string, [summary: string, error: HttpError]>): Json {
  return Object.fromEntries(
    Object.entries(examples).map(([name, [summary, error]]) => [name, { summary, value: errorBody(error) }]),
  );
}

function errorResponse(description: string, examples: Record<string, [string, HttpError]>, headers?: Json): Json {
  return {
    description,
    ...(headers && { headers }),
    content: { 'application/json': { schema: ERROR_SCHEMA, examples: errorExamples(examples) } },
  };
}

// ------------------------------------------------------------------------------- parameters and answers
const OWNER_PARAMETER: Json = {
  name: 'owner',
  in: 'path',
  required: true,
  description: 'The account that owns the repository: OWNER in github.com/OWNER/NAME.',
  schema: { type: 'string', pattern: OWNER_RE.source, minLength: 1, maxLength: OWNER_MAX },
  example: 'ntindle',
};

const NAME_PARAMETER: Json = {
  name: 'name',
  in: 'path',
  required: true,
  description: "The repository's name: NAME in github.com/OWNER/NAME. A .git ending is dropped.",
  schema: { type: 'string', pattern: NAME_RE.source, minLength: 1, maxLength: NAME_MAX, not: { enum: ['.', '..'] } },
  example: 'sossscan',
};

const RETRY_AFTER: Json = {
  description: 'How many seconds to wait before trying again.',
  schema: { type: 'integer', minimum: 1 },
  example: 42,
};

const NO_RESULTS: Json = errorResponse(
  'The scan has no results. A private repository gets exactly the answer a missing one gets.',
  {
    repo_not_found: ['No public repository by this name', noResults([NOT_FOUND])],
    scan_failed: ['GitHub rate-limited the scan', noResults(['repo lookup failed: HTTP 403', RATE_LIMITED])],
  },
);

const RATE_LIMITED_RESPONSE: Json = errorResponse(
  `Too many requests from this IP address, which can make ${allowance('scan')}.`,
  { rate_limited: ['Over the limit', rateLimitError('scan', 42)] },
  { 'Retry-After': RETRY_AFTER },
);

const INTERNAL_ERROR: Json = errorResponse('Something went wrong on the server.', {
  internal_error: ['A crash', internalError()],
});

const SCANNER_BUSY: Json = errorResponse(
  `The request waited 2 minutes for one of the ${MAX_SCANS} scans each server instance runs at once.`,
  { scanner_busy: ['Every scan slot is taken', scannerBusy()] },
);

function reportResponse(cacheControl: string): Json {
  return {
    description: 'The report.',
    headers: { 'Cache-Control': { description: cacheControl, schema: { type: 'string' } } },
    content: {
      'application/json': {
        schema: REPORT_SCHEMA,
        examples: {
          report: { summary: 'A report, trimmed to three of its 44 results', value: EXAMPLE_REPORT },
        },
      },
    },
  };
}

/** No key, token or sign-in: an empty list says so to tools that would otherwise ask for one. */
const NO_AUTH: Json[] = [];

const RATE_LIMIT_NOTE = `Each IP address can make ${allowance('scan')}, GET and POST together.`;

// ---------------------------------------------------------------------------------------------- paths
const PATHS = {
  '/api/scan/{owner}/{name}': {
    get: {
      operationId: 'scanRepository',
      security: NO_AUTH,
      tags: ['Scans'],
      summary: 'Scan a public repository',
      description: [
        'Runs the public scan of github.com/{owner}/{name}, which reads only what anyone can see on GitHub, and returns the report. A new scan takes about 5 to 30 seconds.',
        `The server reuses a scan for ${HOURS} hours, and the CDN in front of it keeps each answer for ${HOURS} hours too, so a report can be up to about ${HOURS * 2} hours old: \`scanned_at\` says when the scan ran, and \`cached\` is true when the server answered from its cache. To scan again sooner, use \`POST /api/scan\` with \`refresh\`.`,
        `A private repository gets the same 404 as one that doesn't exist. To scan one, run the CLI with your own token: ${SITE}/docs/cli.`,
        `${RATE_LIMIT_NOTE} A request the CDN answers doesn't count.`,
      ].join('\n\n'),
      parameters: [OWNER_PARAMETER, NAME_PARAMETER],
      responses: {
        200: reportResponse(
          `\`${SCAN_CACHE_CONTROL}\`, so the CDN keeps the answer for ${HOURS} hours, or \`no-store\` when GitHub rate-limited the scan, since some of its answers may be wrong.`,
        ),
        404: NO_RESULTS,
        422: errorResponse("The owner or the name isn't one GitHub allows.", {
          invalid_repo: ['Not a repository name', invalidRepo()],
        }),
        429: RATE_LIMITED_RESPONSE,
        500: INTERNAL_ERROR,
        503: SCANNER_BUSY,
      },
    },
  },
  '/api/scan': {
    post: {
      operationId: 'rescanRepository',
      security: NO_AUTH,
      tags: ['Scans'],
      summary: 'Scan a public repository, with the option to skip the cache',
      description: [
        "The same scan as `GET /api/scan/{owner}/{name}`, with the repository in a JSON body. With `refresh: true`, the server skips its cache and scans again; the site's Rescan button sends that.",
        'The answer has `Cache-Control: no-store`, so the CDN never keeps it, but the server saves a new scan in its cache.',
        RATE_LIMIT_NOTE,
      ].join('\n\n'),
      requestBody: {
        required: true,
        content: {
          'application/json': {
            schema: SCAN_REQUEST_SCHEMA,
            examples: {
              rescan: { summary: 'Scan again, skipping the cache', value: { repo: 'ntindle/sossscan', refresh: true } },
              url: { summary: 'A github.com URL', value: { repo: 'https://github.com/ntindle/sossscan' } },
            },
          },
        },
      },
      responses: {
        200: reportResponse('`no-store`: nothing keeps the answer.'),
        404: NO_RESULTS,
        422: errorResponse("The body isn't a JSON object with a valid `repo`.", {
          missing_repo: ['No repo in the body', thrown(() => field({}, 'repo', REPO_LENGTH))],
          invalid_repo: ['Not a repository', invalidRepo()],
        }),
        429: RATE_LIMITED_RESPONSE,
        500: INTERNAL_ERROR,
        503: SCANNER_BUSY,
      },
    },
  },
  '/api/health': {
    get: {
      operationId: 'getHealth',
      security: NO_AUTH,
      tags: ['Service'],
      summary: 'Check that the service is up',
      description:
        "Says that the server is up and which scanner version it runs. It says nothing else about the server, and it isn't rate limited.",
      responses: {
        200: {
          description: 'The server is up.',
          headers: { 'Cache-Control': { description: '`no-store`.', schema: { type: 'string' } } },
          content: {
            'application/json': {
              schema: HEALTH_SCHEMA,
              examples: { up: { summary: 'Up', value: { ok: true, scanner_version: VERSION } } },
            },
          },
        },
        500: INTERNAL_ERROR,
      },
    },
  },
};

// ----------------------------------------------------------------------------------------- the document
/** Every named part of the document, by kind, as components lists them. */
const COMPONENTS: Record<string, Record<string, Json>> = {
  schemas: SCHEMAS,
  parameters: { Owner: OWNER_PARAMETER, Name: NAME_PARAMETER },
  headers: { RetryAfter: RETRY_AFTER },
  responses: {
    NoResults: NO_RESULTS,
    RateLimited: RATE_LIMITED_RESPONSE,
    InternalError: INTERNAL_ERROR,
    ScannerBusy: SCANNER_BUSY,
  },
};

/** A copy of `value` with each named part inside it, other than `top` itself, replaced by a $ref to its name. */
function withRefs(value: unknown, names: Map<unknown, string>, top?: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (value !== top && names.has(value)) return { $ref: names.get(value) };
  if (Array.isArray(value)) return value.map((item) => withRefs(item, names));
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, withRefs(item, names)]));
}

/** The OpenAPI document. It's the same every time, so the route builds it once, when the site builds. */
export function openApiDocument(): Json {
  const names = new Map<unknown, string>();
  for (const [kind, group] of Object.entries(COMPONENTS)) {
    for (const [name, part] of Object.entries(group)) names.set(part, `#/components/${kind}/${name}`);
  }
  return {
    openapi: '3.1.1',
    info: {
      title: 'sossscan API',
      version: pkg.version,
      summary: 'Scan a public GitHub repository for security gaps and get a JSON report.',
      description: [
        "sossscan checks how a GitHub repository is set up for security, from who can push and publish to how people report vulnerabilities, and says which gap to close first. This API runs the public scan of a public repository and returns the report. There's no key and no sign-in.",
        "Every error under /api/ has the same body: a code that a program can rely on, a message, and a hint that says what to do next. An address under /api/ with no endpoint gets 404 `not_found`, and a method an endpoint doesn't take gets 405 `method_not_allowed`, with an `Allow` header.",
        `${RATE_LIMIT_NOTE} The API sends no CORS headers, so a web page on another site can't read its answers.`,
        "The endpoints under /api/app/ serve the site's GitHub App features: sign-in, Deep scan and fixes. They need a signed-in browser and a header only the site's page sends, so this document leaves them out.",
      ].join('\n\n'),
      contact: { name: 'sossscan', url: `${SITE}/contact`, email: 'sossscan@ntindle.com' },
      license: { name: 'MIT', identifier: 'MIT' },
    },
    servers: [{ url: SITE, description: 'The live site' }],
    externalDocs: { description: 'The API docs, with the report format and the limits', url: `${SITE}/docs/api` },
    tags: [
      { name: 'Scans', description: 'Scan public repositories on github.com.' },
      { name: 'Service', description: 'Whether the service is up.' },
    ],
    paths: withRefs(PATHS, names),
    components: Object.fromEntries(
      Object.entries(COMPONENTS).map(([kind, group]) => [
        kind,
        Object.fromEntries(Object.entries(group).map(([name, part]) => [name, withRefs(part, names, part)])),
      ]),
    ),
  };
}
