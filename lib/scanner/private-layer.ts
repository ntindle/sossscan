// Admin-only settings, ported from private_layer() in the Python scanner. Runs only when the token has admin on
// the repo (or the caller vouches for it, as the GitHub App does).
import { mapLimit } from '../pool.ts';
import type { Http } from './http.ts';
import { get, isDict, item, pyIn, pyIter, pyJoin, pyLenOf, pyOr, pyStr, quote, truthy } from './py.ts';
import type { Evidence, Finding, Report, Status } from './types.ts';

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
) => void;

const P = 'private';

export async function privateLayer(
  http: Http,
  rep: Report,
  repo: string,
  owner: string,
  branch: string,
  meta: any,
  res: AddResult,
  finding: AddFinding,
): Promise<void> {
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
  ];
  if (item(item(meta, 'owner'), 'type') === 'Organization') {
    calls.push(['org', `/orgs/${owner}`], ['no2fa', `/orgs/${owner}/members?filter=2fa_disabled&per_page=100`]);
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
    const good =
      get(wp, 'default_workflow_permissions') === 'read' && !truthy(get(wp, 'can_approve_pull_request_reviews'));
    const prev = get(R, 'ci-token-permissions', {});
    const prevStatus = get(prev, 'status');
    res(
      'ci-token-permissions',
      good && (prevStatus === 'pass' || prevStatus === null || prevStatus === 'na')
        ? 'pass'
        : good || prevStatus === 'pass'
          ? 'warn'
          : 'fail',
      `Default GITHUB_TOKEN: ${pyStr(get(wp, 'default_workflow_permissions'))}; ` +
        `Actions can approve PRs: ${pyStr(get(wp, 'can_approve_pull_request_reviews'))}. ` +
        get(prev, 'summary', ''),
      null,
      { ...get(prev, 'details', {}), ...wp },
      P,
    );
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
    if (get(prev, 'status') !== 'pass') {
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
  } else {
    unreadable('ci-secrets-hygiene', 'the repository Actions secrets', 'secrets');
  }
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
}
