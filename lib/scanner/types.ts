// The report the scanner writes (schema sosf-scan/1). Key names are the Python ones, because the site's browser
// code (public/shared/core.js, public/pipeline/pipeline.js) reads them as they are.

export type Status = 'pass' | 'warn' | 'fail' | 'info' | 'unknown' | 'na';

export interface Evidence {
  label: string;
  url: string;
}

export interface Result {
  status: Status;
  summary: string;
  evidence: Evidence[];
  details: Record<string, any>;
  layer: 'public' | 'private';
}

export interface Finding {
  item_id: string;
  severity: 'high' | 'medium' | 'low';
  title: string;
  path: string | null;
  line: number | null;
  url: string | null;
  hint: string | null;
}

export interface RepoMeta {
  stars: number;
  forks: number;
  watchers: number | null;
  dependents: { repositories: number; packages: number } | null;
  dependents_total: number | null;
  language: string | null;
  topics: string[];
  default_branch: string;
  archived: boolean | null;
  private: boolean;
  owner_type: string;
  /** When GitHub says the repository was created (ISO 8601). It decides the token default a public scan assumes. */
  created_at: string | null;
  description: string | null;
  ecosystems: string[];
  workflow_count: number;
  publishes_from_ci: boolean;
  html_url: string | null;
  has_security_tab: true;
  admin_token: boolean;
  /** Private layer only. */
  open_dependabot_alerts?: { total: number; critical_high: number };
  /** Private layer only. */
  allowed_actions?: string | null;
}

export interface Scorecard {
  score: number | null;
  date: string;
  checks: Record<string, number | null>;
  reasons: Record<string, string | null>;
}

export interface Report {
  schema: string;
  tool: { name: string; version: string };
  repo: string;
  scanned_at: string;
  /** 'app' is set by the server after a GitHub App scan; the scanner itself writes 'public' or 'private'. */
  layer: 'public' | 'private' | 'app';
  /** Empty when the repo couldn't be read. */
  meta: Partial<RepoMeta>;
  results: Record<string, Result>;
  findings: Finding[];
  errors: string[];
  scorecard: Scorecard | null;
  /** The keys below are missing when the scan stopped early (see errors). */
  tier?: { id: number; name: string };
  summary?: Record<Status, number>;
  api_calls?: number;
}

/** What analyzeWorkflow finds in one workflow file. The optional keys are only present when set, as in Python. */
export interface WorkflowAnalysis {
  path: string;
  uses: string[];
  unpinned: { line: number; ref: string }[];
  checkouts: number;
  checkouts_no_persist: number[];
  /** One entry per distinct untrusted expression in a run: or script: line, so a line can have several. */
  risky_lines: { line: number; expr: string }[];
  top_permissions: boolean;
  write_all: boolean;
  /** Has a pull_request_target trigger. */
  prt: boolean;
  /** Has a pull_request trigger (fork PRs run these too, without secrets). */
  pull_request: boolean;
  workflow_run: boolean;
  id_token_write: boolean;
  unsafe_pr_checkout: boolean;
  self_hosted: boolean;
  tools: string[];
  /** Only when there is no top-level permissions block. */
  job_permissions_all?: boolean;
  /** Lines of checkouts of the PR head in a pull_request_target workflow. */
  prt_checks_out_pr?: number[];
  /** Only when the workflow uses CodeQL. */
  codeql_actions?: boolean;
  workflow_run_untrusted?: true;
}

export interface ScanOptions {
  token?: string | null;
  /** 'public' skips admin-only checks even if the token could see them. */
  layer?: 'public' | 'private';
  log?: (msg: string) => void;
  /**
   * Which OSS-Fuzz projects build this repo; without it the scanner guesses project names and checks them. Neither
   * happens for a private repo.
   */
  ossFuzzLookup?: ((repo: string) => string[]) | null;
  /** Run the private layer even though the token's permissions aren't reported (GitHub App installation tokens). */
  assumeAdmin?: boolean;
  /**
   * The permissions the token holds, when the caller knows them: a GitHub App installation token's, as GitHub gave
   * them with it. An admin check whose permission is missing then says so, and an empty list it gets isn't read as none.
   */
  grants?: Record<string, string> | null;
  /** false refuses private repositories (the shared web server, whose token must not expose them). */
  allowPrivate?: boolean;
}
