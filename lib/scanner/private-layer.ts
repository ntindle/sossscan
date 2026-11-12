// Admin-only settings, ported from private_layer() in the Python scanner. Runs only when the token has admin on
// the repo (or the caller vouches for it, as the GitHub App does).
import { mapLimit } from '../pool.ts';
import {
  advisoriesLink,
  advisoryFacts,
  canReadUnpublished,
  lastDrill,
  showsUnpublished,
  waitingReports,
} from './advisories.ts';
import type { Answer } from './advisories.ts';
import type { Http } from './http.ts';
import { get, isDict, item, pyIn, pyIter, pyJoin, pyLenOf, pyOr, pyStr, quote, truthy } from './py.ts';
import type { Evidence, Finding, Report, Result, Status } from './types.ts';

export type AddResult = (
  itemId: string,
  status: Status,
  summary: string,
  evidence?: Evidence[] | null,
  details?: Record<string, any> | null,
  lay?: 'public' | 'private',
) => void;

export type AddFinding = (
  itemId: string,
  severity: Finding['severity'],
  title: string,
  path?: string | null,
  line?: number | null,
  hint?: string | null,
) => Finding;

const P = 'private';

/** What else the private layer knows about the token, and what the public layer read that it uses. */
export interface PrivateContext {
  /** The token is the GitHub App's installation token, whose permissions are the app's, not an admin's. */
  app?: boolean;
  /** The permissions the token holds, when known: an installation token's, as GitHub gave them. */
  grants?: Record<string, string> | null;
  /** A classic token's scopes (GitHub's X-OAuth-Scopes header); null for a token without them. */
  scopes?: string[] | null;
  /** The published advisories the public layer listed. */
  published?: unknown[];
}

/**
 * noBlock: the findings for workflows without a permissions block. Their token gets the repository's default, which
 * the public layer could only guess at; they're reworded here once the default is read. rulesetsFailed: the HTTP status
 * of the public layer's rulesets lookup if GitHub didn't answer it, which leaves unknown whether a tag ruleset exists.
 */
export async function privateLayer(
  http: Http,
  rep: Report,
  repo: string,
  owner: string,
  branch: string,
  meta: any,
  res: AddResult,
  finding: AddFinding,
  noBlock: Finding[],
  rulesetsFailed: number | null,
  ctx: PrivateContext = {},
): Promise<void> {
  const app = ctx.app ?? false;
  const calls: [string, string][] = [
    ['vuln_alerts', `/repos/${repo}/vulnerability-alerts`],
    ['autofix', `/repos/${repo}/automated-security-fixes`],
    ['default_setup', `/repos/${repo}/code-scanning/default-setup`],
    ['actions', `/repos/${repo}/actions/permissions`],
    ['wf_perms', `/repos/${repo}/actions/permissions/workflow`],
    ['fork', `/repos/${repo}/actions/permissions/fork-pr-contributor-approval`],
    ['protection', `/repos/${repo}/branches/${quote(branch)}/protection`],
    ['immutable', `/repos/${repo}/immutable-releases`],
    ['envs', `/repos/${repo}/environments`],
    ['cs_alerts', `/repos/${repo}/code-scanning/alerts?state=open&per_page=100`],
    ['ss_alerts', `/repos/${repo}/secret-scanning/alerts?state=open&per_page=100`],
    ['dep_alerts', `/repos/${repo}/dependabot/alerts?state=open&per_page=100`],
    ['admins', `/repos/${repo}/collaborators?affiliation=all&permission=admin&per_page=100`],
    ['secrets', `/repos/${repo}/actions/secrets?per_page=1`],
    // New in 0.5.2, for counts and dates only (advisories.ts): the private vulnerability reports in triage, oldest
    // first; the closed advisories, latest first, for a drill; and the drafts, for who worked on them.
    ['triage', `/repos/${repo}/security-advisories?state=triage&sort=created&direction=asc&per_page=100`],
    ['closed', `/repos/${repo}/security-advisories?state=closed&sort=updated&per_page=100`],
    ['drafts', `/repos/${repo}/security-advisories?state=draft&per_page=100`],
  ];
  const isOrg = item(item(meta, 'owner'), 'type') === 'Organization';
  if (isOrg) {
    calls.push(
      ['org', `/orgs/${owner}`],
      ['no2fa', `/orgs/${owner}/members?filter=2fa_disabled&per_page=100`],
      // New in 0.5.0: the members who still have SMS for 2FA (an owner-only filter), and the org's security
      // configuration for this repo and for new ones.
      ['sms2fa', `/orgs/${owner}/members?filter=2fa_insecure&per_page=100`],
      ['security_config', `/repos/${repo}/code-security-configuration`],
      ['config_defaults', `/orgs/${owner}/code-security/configurations/defaults`],
    );
  }
  const answers = await mapLimit(calls, 8, ([, path]) => http.json(path));
  const got: Record<string, [number, any, Record<string, string>]> = Object.fromEntries(
    calls.map(([key], i) => [key, answers[i]]),
  );
  const ok = (k: string) => got[k][0] === 200 && got[k][1] !== null;
  // An item only this layer can check, whose call failed: report that it couldn't be read and why, instead of leaving
  // it out (the site would then say it needs the private scan, which just ran).
  const unreadable = (itemId: string, what: string, k: string) =>
    res(itemId, 'unknown', `Could not read ${what} (HTTP ${got[k][0]})`, null, null, P);
  const R = rep.results;

  const sa = pyOr(get(meta, 'security_and_analysis'), {});
  const on = (k: string) => get(pyOr(get(sa, k), {}), 'status') === 'enabled';
  if (truthy(sa)) {
    res(
      'secrets-scanning',
      on('secret_scanning') ? 'pass' : 'fail',
      'GitHub secret scanning is ' + (on('secret_scanning') ? 'on' : 'off'),
      null,
      null,
      P,
    );
    res(
      'secrets-push-protection',
      on('secret_scanning_push_protection') ? 'pass' : 'fail',
      'Push protection is ' + (on('secret_scanning_push_protection') ? 'on' : 'off'),
      null,
      null,
      P,
    );
  }
  const va = got.vuln_alerts[0];
  const autofix = ok('autofix') ? get(pyOr(got.autofix[1], {}), 'enabled') : null;
  if (va === 204 || va === 404) {
    res(
      'deps-alerts',
      va === 204 && truthy(autofix) ? 'pass' : va === 204 ? 'warn' : 'fail',
      'Dependabot alerts ' +
        (va === 204 ? 'on' : 'off') +
        (truthy(autofix) ? ', security updates on' : ', security updates off'),
      null,
      null,
      P,
    );
  } else {
    unreadable('deps-alerts', 'the Dependabot alerts setting', 'vuln_alerts');
  }
  const ds = ok('default_setup') ? got.default_setup[1] : null;
  if (truthy(ds) && get(ds, 'state') === 'configured') {
    const languages = pyOr(get(ds, 'languages'), []);
    res('sast-codeql', 'pass', 'CodeQL default setup is configured: ' + pyJoin(', ', pyIter(languages)), null, null, P);
    res(
      'sast-codeql-actions',
      pyIn('actions', languages) ? 'pass' : 'fail',
      pyIn('actions', languages) ? "CodeQL scans 'actions'" : "CodeQL default setup does not include 'actions'",
      null,
      null,
      P,
    );
  }
  if (ok('cs_alerts')) {
    // OpenSSF Scorecard uploads its results as code scanning alerts too. They grade settings and habits (branch
    // protection, code review, the repo's age), not code, so they're named apart and left out of the backlog.
    const isScorecard = (a: unknown) =>
      String(get(pyOr(get(a, 'tool'), {}), 'name') ?? '').toLowerCase() === 'scorecard';
    const page = pyIter(got.cs_alerts[1]);
    const alerts = page.filter((a) => !isScorecard(a));
    const scorecard = page.length - alerts.length;
    const hi = alerts.filter((a) =>
      pyIn(get(pyOr(get(a, 'rule'), {}), 'security_severity_level'), ['critical', 'high']),
    ).length;
    const more = pyLenOf(got.cs_alerts[1]) === 100 ? '+' : '';
    res(
      'sast-fix-backlog',
      !alerts.length ? 'pass' : !hi ? 'warn' : 'fail',
      `${alerts.length}${more} open code scanning alerts (${hi} critical/high)` +
        (scorecard
          ? `, not counting ${scorecard}${more} OpenSSF Scorecard results, which grade settings rather than code`
          : ''),
      [{ label: 'Code scanning', url: `https://github.com/${repo}/security/code-scanning` }],
      scorecard ? { scorecard_alerts: scorecard } : null,
      P,
    );
  } else {
    unreadable('sast-fix-backlog', 'the open code scanning alerts', 'cs_alerts');
  }
  if (ok('ss_alerts')) {
    const n = pyLenOf(got.ss_alerts[1]);
    res(
      'secrets-rotate-leaked',
      !n ? 'pass' : 'fail',
      `${n} open secret scanning alerts`,
      [{ label: 'Secret scanning', url: `https://github.com/${repo}/security/secret-scanning` }],
      null,
      P,
    );
  } else {
    unreadable('secrets-rotate-leaked', 'the open secret scanning alerts', 'ss_alerts');
  }
  if (ok('dep_alerts')) {
    const alerts = got.dep_alerts[1];
    const crit = pyIter(alerts).filter((a) =>
      pyIn(get(pyOr(get(a, 'security_advisory'), {}), 'severity'), ['critical', 'high']),
    ).length;
    rep.meta.open_dependabot_alerts = { total: pyLenOf(alerts), critical_high: crit };
    if (crit) {
      finding(
        'deps-alerts',
        'high',
        `${crit} open critical/high Dependabot alerts`,
        null,
        null,
        'Merge the security updates or dismiss with a reason',
      );
    }
  }
  if (ok('wf_perms')) {
    const wp = got.wf_perms[1];
    if (!isDict(wp)) throw new TypeError("'**' argument must be a mapping");
    const dflt = get(wp, 'default_workflow_permissions');
    const canApprove = truthy(get(wp, 'can_approve_pull_request_reviews'));
    const good = dflt === 'read' && !canApprove;
    const prev = get(R, 'ci-token-permissions', {});
    const prevStatus = get(prev, 'status');
    const access = dflt === 'read' ? 'read-only' : dflt === 'write' ? 'read and write' : pyStr(dflt ?? 'unknown');
    res(
      'ci-token-permissions',
      good && (prevStatus === 'pass' || prevStatus === null || prevStatus === 'na')
        ? 'pass'
        : good || prevStatus === 'pass'
          ? 'warn'
          : 'fail',
      `Default GITHUB_TOKEN: ${access}; Actions ${canApprove ? 'can' : "can't"} approve pull requests. ` +
        get(prev, 'summary', ''),
      null,
      { ...get(prev, 'details', {}), ...wp },
      P,
    );
    // Letting Actions approve pull requests doesn't widen a read-only token: approving takes pull-requests: write, which
    // the read-only default doesn't give. So the default alone decides what these workflows' token can do.
    for (const f of noBlock) {
      if (dflt === 'read') {
        f.severity = 'low';
        f.title =
          'No permissions block: the token is read-only today through the repository default, and declaring ' +
          'permissions keeps it that way if the default changes';
      } else if (dflt === 'write') {
        f.severity = 'high';
        f.title = "No permissions block, so this workflow's token gets the repository's read-and-write default";
      }
    }
  }
  if (ok('actions')) {
    const ap = got.actions[1];
    if (truthy(get(ap, 'sha_pinning_required'))) {
      res('ci-pin-actions', 'pass', 'The repo requires actions to be pinned to full commit SHAs', null, null, P);
    }
    rep.meta.allowed_actions = get(ap, 'allowed_actions');
  }
  if (ok('fork')) {
    const pol = get(got.fork[1], 'approval_policy');
    res(
      'ci-fork-pr-approval',
      pyIn(pol, ['first_time_contributors', 'all_external_contributors']) ? 'pass' : 'warn',
      `Fork PR workflows need approval for: ${pyStr(pol)}`,
      null,
      null,
      P,
    );
  } else {
    unreadable('ci-fork-pr-approval', 'the fork PR approval policy', 'fork');
  }
  if (ok('protection')) {
    const pr = got.protection[1];
    const rv = pyOr(get(pr, 'required_pull_request_reviews'), {});
    const det = {
      reviews: get(rv, 'required_approving_review_count', 0),
      code_owner_reviews: get(rv, 'require_code_owner_reviews', false),
      enforce_admins: get(pyOr(get(pr, 'enforce_admins'), {}), 'enabled'),
      force_push: get(pyOr(get(pr, 'allow_force_pushes'), {}), 'enabled'),
    };
    const st = truthy(det.reviews) && !truthy(det.force_push) ? 'pass' : 'warn';
    res(
      'repo-branch-protection',
      st,
      `Branch protection: ${pyStr(det.reviews)} review(s) required, force-push ` +
        (truthy(det.force_push) ? 'allowed' : 'blocked'),
      null,
      det,
      P,
    );
  }
  if (ok('immutable') && truthy(get(got.immutable[1], 'enabled'))) {
    res('repo-tag-release-protection', 'pass', 'Immutable releases are enabled', null, null, P);
  } else if (ok('immutable')) {
    const prev = get(R, 'repo-tag-release-protection', {});
    if (get(prev, 'status') !== 'pass' && rulesetsFailed !== null) {
      res(
        'repo-tag-release-protection',
        'unknown',
        `Immutable releases are off, and the tag rulesets couldn't be checked (HTTP ${rulesetsFailed})`,
        null,
        null,
        P,
      );
    } else if (get(prev, 'status') !== 'pass') {
      res(
        'repo-tag-release-protection',
        'fail',
        'Immutable releases are off and no tag ruleset protects release tags',
        null,
        null,
        P,
      );
    }
  }
  if (ok('envs')) {
    const envs = pyIter(get(got.envs[1], 'environments', []));
    const gated = envs
      .filter((e) => pyIter(get(e, 'protection_rules', [])).some((r) => get(r, 'type') === 'required_reviewers'))
      .map((e) => item(e, 'name'));
    res(
      'rel-gated-release',
      gated.length ? 'pass' : envs.length ? 'info' : 'fail',
      gated.length
        ? `Environments with required reviewers: ${pyJoin(', ', gated)}`
        : envs.length
          ? `${envs.length} environment(s), none require a reviewer`
          : 'No deployment environments (releases are not gated)',
      null,
      null,
      P,
    );
  } else {
    unreadable('rel-gated-release', 'the environment protection rules', 'envs');
  }
  if (ok('admins')) {
    const admins = got.admins[1];
    const nAdmin = pyLenOf(admins);
    res(
      'acct-least-privilege',
      nAdmin <= 3 ? 'pass' : 'warn',
      `${nAdmin} account(s) with admin on this repo`,
      null,
      {
        admins: pyIter(admins)
          .map((a) => item(a, 'login'))
          .slice(0, 20),
      },
      P,
    );
  } else {
    unreadable('acct-least-privilege', 'the accounts with admin on this repo', 'admins');
  }
  if (ok('secrets')) {
    res(
      'ci-secrets-hygiene',
      'info',
      `${pyStr(get(got.secrets[1], 'total_count', 0))} repository Actions secret(s); prefer environment secrets and OIDC`,
      null,
      null,
      P,
    );
  } else if (app && got.secrets[0] === 403 && !granted(ctx.grants, 'secrets')) {
    // The installation hasn't accepted the app's "Secrets: read" permission (it reads names and dates, never values).
    res(
      'ci-secrets-hygiene',
      'unknown',
      "Couldn't read the names of Actions secrets: the GitHub App hasn't been given access to them on this " +
        "installation. An owner can approve the new permission in the installation's settings, or use the CLI " +
        "with an admin's token",
      null,
      null,
      P,
    );
  } else {
    unreadable('ci-secrets-hygiene', 'the repository Actions secrets', 'secrets');
  }
  unpublishedAdvisories({ triage: got.triage, closed: got.closed, drafts: got.drafts }, repo, ctx, R, res);
  if (Object.hasOwn(got, 'org')) {
    const org = ok('org') ? got.org[1] : {};
    const req = get(org, 'two_factor_requirement_enabled');
    if (req !== null) {
      const no2fa = ok('no2fa') ? pyLenOf(got.no2fa[1]) : null;
      res(
        'acct-2fa-required',
        truthy(req) ? 'pass' : 'fail',
        truthy(req)
          ? 'Org requires 2FA'
          : 'Org does not require 2FA' + (no2fa ? `; ${no2fa} member(s) without 2FA` : ''),
        null,
        null,
        P,
      );
    } else {
      res('acct-2fa-required', 'unknown', 'Org 2FA requirement needs an org owner token', null, null, P);
    }
  } else {
    res(
      'acct-2fa-required',
      'na',
      'Personal repository: turn on 2FA (ideally a passkey) for your account',
      null,
      null,
      P,
    );
  }
  if (isOrg) {
    smsTwoFactor(got.sms2fa, res);
    securityConfiguration(got.security_config, got.config_defaults, meta, res);
  } else {
    res('repo-org-security-config', 'na', 'Personal accounts have no security configurations', null, null, P);
  }
}

/** Whether the token is known to hold a permission, read or write. */
function granted(grants: Record<string, string> | null | undefined, name: string): boolean {
  return !!grants && (grants[name] === 'read' || grants[name] === 'write');
}

/**
 * The self-checks the unpublished advisories can show (new in 0.5.2): disc-triage-sla warns when private vulnerability
 * reports have waited over 14 days with no comment, plan-irp-exercise passes on a practice advisory titled DRILL closed
 * in the last 12 months, and disc-coordinated-disclosure counts the advisories that brought in collaborators or have a
 * temporary private fork. Each list is reduced to counts and dates first (advisoryFacts), and the results say nothing
 * else about any report. An empty list means something only when the token is known to read unpublished advisories,
 * or GitHub listed one: a token that can't gets an empty list too. Each adds to what the public layer found (in R).
 */
export function unpublishedAdvisories(
  answers: { triage: Answer; closed: Answer; drafts: Answer },
  repo: string,
  ctx: PrivateContext,
  R: Record<string, Result>,
  res: AddResult,
  now: Date = new Date(),
): void {
  const triage = advisoryFacts(answers.triage, 'triage');
  const closed = advisoryFacts(answers.closed, 'closed');
  const drafts = advisoryFacts(answers.drafts, 'draft');
  const known = canReadUnpublished(ctx.grants, ctx.scopes);
  const access =
    known === true ||
    showsUnpublished(answers.triage, 'triage') ||
    showsUnpublished(answers.closed, 'closed') ||
    showsUnpublished(answers.drafts, 'draft');

  // disc-triage-sla. Oldest first, so a full page holds the oldest reports, though not every one waiting.
  const before = R['disc-triage-sla'];
  const policyLinks = before?.evidence ?? [];
  if (access && triage) {
    const full = pyLenOf(answers.triage[1]) >= 100;
    const { waiting, oldest } = waitingReports(triage, now);
    if (waiting) {
      const n = `${waiting}${full ? '+' : ''}`;
      res(
        'disc-triage-sla',
        'warn',
        n === '1'
          ? `1 private vulnerability report has waited ${oldest} days with no comment`
          : `${n} private vulnerability reports have waited over 14 days with no comment, ` +
              `the oldest for ${oldest} days`,
        [advisoriesLink(repo, 'triage'), ...policyLinks],
        { waiting: n, oldest_days: oldest },
        P,
      );
    } else if (!full) {
      const fact = triage.length
        ? `${triage.length} private vulnerability report${triage.length === 1 ? ' is' : 's are'} in triage, none ` +
          'waiting over 14 days with no comment'
        : 'no private vulnerability reports are waiting in triage';
      res(
        'disc-triage-sla',
        'info',
        before ? `${before.summary}; ${fact}` : fact.charAt(0).toUpperCase() + fact.slice(1),
        [advisoriesLink(repo, 'triage'), ...policyLinks],
        { in_triage: triage.length },
        P,
      );
    }
  } else if (!before && (known === false || triage === null)) {
    res(
      'disc-triage-sla',
      'unknown',
      known === false && ctx.app
        ? "Couldn't read the private vulnerability reports: the GitHub App hasn't been given access to security " +
            "advisories on this installation. An owner can approve the new permission in the installation's " +
            "settings, or use the CLI with an admin's token"
        : known === false
          ? "Couldn't read the private vulnerability reports: the token needs the repo scope"
          : `Could not read the private vulnerability reports (HTTP ${answers.triage[0]})`,
      null,
      null,
      P,
    );
  }

  // plan-irp-exercise: the latest closed advisories, for a drill.
  const plan = R['plan-irp-exercise'];
  const last = access && closed ? lastDrill(closed, now) : null;
  if (last?.recent) {
    res(
      'plan-irp-exercise',
      'pass',
      `A practice advisory titled DRILL was closed on ${last.date}, within the last 12 months`,
      [advisoriesLink(repo, 'closed')],
      { drill_closed: last.date },
      P,
    );
  } else if (last) {
    res(
      'plan-irp-exercise',
      'info',
      `The last practice advisory titled DRILL was closed on ${last.date}, over 12 months ago` +
        (plan ? `; ${plan.summary}` : ''),
      [advisoriesLink(repo, 'closed'), ...(plan?.evidence ?? [])],
      { drill_closed: last.date },
      P,
    );
  }

  // disc-coordinated-disclosure: the advisories the maintainers brought collaborators into, or that have a temporary
  // private fork. Not the reports still in triage: a reporter can start a fork when they send one.
  if (access) {
    const all = [
      ...(drafts ?? []),
      ...(closed ?? []),
      ...(advisoryFacts([200, ctx.published ?? [], {}], 'published') ?? []),
    ];
    const people = all.filter((f) => f.collaborators).length;
    const forks = all.filter((f) => f.fork).length;
    if (people || forks) {
      const of = `of ${all.length} advisor${all.length === 1 ? 'y' : 'ies'}`;
      const has = forks === 1 ? 'has' : 'have';
      const part =
        people && forks
          ? `${people} ${of} brought in collaborators, and ${forks} ${has} a temporary private fork`
          : people
            ? `${people} ${of} brought in collaborators`
            : `${forks} ${of} ${has} a temporary private fork`;
      const prev = R['disc-coordinated-disclosure'];
      const links = prev?.evidence ?? [];
      res(
        'disc-coordinated-disclosure',
        'info',
        prev ? `${prev.summary}; ${part}` : part,
        links.some((e) => e.url === advisoriesLink(repo).url) ? links : [...links, advisoriesLink(repo)],
        { ...(prev?.details ?? {}), advisories: all.length, with_collaborators: people, with_private_fork: forks },
        P,
      );
    }
  }
}

/**
 * acct-phishing-resistant-2fa (new in 0.5.0): the org members who still have SMS for 2FA, which only an org owner can
 * list. A refusal leaves the check unknown, never passed or warned. No member on SMS is still no proof of passkeys,
 * since GitHub counts an authenticator app as secure too, so that's info.
 */
export function smsTwoFactor([status, body]: [number, any, Record<string, string>], res: AddResult): void {
  if (status !== 200 || !Array.isArray(body)) {
    res(
      'acct-phishing-resistant-2fa',
      'unknown',
      `Could not count the org members who use SMS for 2FA (HTTP ${status}); only an org owner can`,
      null,
      null,
      P,
    );
    return;
  }
  const n = body.length;
  const more = n === 100 ? '+' : '';
  if (n) {
    res(
      'acct-phishing-resistant-2fa',
      'warn',
      `${n}${more} org member${n === 1 ? '' : 's'} still ${n === 1 ? 'has' : 'have'} SMS for 2FA; turn on "Only ` +
        'allow secure two-factor methods" in the org\'s authentication settings',
      null,
      { members_with_sms: `${n}${more}` },
      P,
    );
  } else {
    res(
      'acct-phishing-resistant-2fa',
      'info',
      'No org member uses SMS for 2FA. GitHub counts an authenticator app as secure too, so a passkey or security ' +
        'key is still for each person to set up',
      null,
      null,
      P,
    );
  }
}

/** Visibilities a default for new repositories applies to (default_for_new_repos). */
const DEFAULT_COVERS: Record<string, string[]> = {
  all: ['public', 'private', 'internal'],
  public: ['public'],
  private_and_internal: ['private', 'internal'],
};

/**
 * repo-org-security-config (new in 0.5.0), for an org's repo: is one of the org's code security configurations
 * attached to it, and is there a default that new repositories with its visibility get? A 204 is GitHub's answer for
 * no configuration; a refusal (403 or 404) leaves the check unknown.
 */
export function securityConfiguration(
  [status, body]: [number, any, Record<string, string>],
  [dStatus, defaults]: [number, any, Record<string, string>],
  meta: any,
  res: AddResult,
): void {
  const name = (b: any) => {
    const n = isDict(b) && isDict(b.configuration) ? b.configuration.name : null;
    return typeof n === 'string' && n ? `"${n}"` : 'The security configuration';
  };
  if (status === 204) {
    res('repo-org-security-config', 'fail', 'No security configuration is applied to this repository', null, null, P);
    return;
  }
  if (status !== 200 || !isDict(body)) {
    res(
      'repo-org-security-config',
      'unknown',
      `Could not read the repository's security configuration (HTTP ${status})`,
      null,
      null,
      P,
    );
    return;
  }
  const state = String(body.status ?? '');
  if (['removed', 'detached', 'failed', 'removed_by_enterprise'].includes(state)) {
    res(
      'repo-org-security-config',
      'warn',
      `${name(body)} no longer manages this repository (status: ${state}), so its settings may have drifted`,
      null,
      { status: state },
      P,
    );
    return;
  }
  if (state === 'attaching' || state === 'updating') {
    res('repo-org-security-config', 'info', `GitHub is still applying ${name(body)} (status: ${state})`, null, null, P);
    return;
  }
  if (state !== 'attached' && state !== 'enforced') {
    res('repo-org-security-config', 'unknown', `Unexpected security configuration status: ${state}`, null, null, P);
    return;
  }
  const visibility =
    typeof get(meta, 'visibility') === 'string'
      ? get(meta, 'visibility')
      : truthy(get(meta, 'private'))
        ? 'private'
        : 'public';
  if (dStatus !== 200 || !Array.isArray(defaults)) {
    res(
      'repo-org-security-config',
      'unknown',
      `${name(body)} is ${state} here, but the org's defaults for new repositories couldn't be read (HTTP ${dStatus})`,
      null,
      { status: state },
      P,
    );
    return;
  }
  const covering = defaults.find(
    (d) => isDict(d) && (DEFAULT_COVERS[String(d.default_for_new_repos)] ?? []).includes(visibility),
  );
  res(
    'repo-org-security-config',
    covering ? 'pass' : 'warn',
    covering
      ? `${name(body)} is ${state} here, and new ${visibility} repositories get ${name(covering)} by default`
      : `${name(body)} is ${state} here, but new ${visibility} repositories get no configuration by default`,
    null,
    { status: state, visibility },
    P,
  );
}
