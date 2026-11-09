// Names, tiers and patterns shared by the scanner. Every regex here is copied verbatim from the Python scanner
// (scanner/sosf_scan.py in commit a55738d), in Python syntax compiled by re() in py.ts.
import { re } from './py.ts';

export const VERSION = '0.4.1';
export const SCHEMA = 'sosf-scan/1';
export const UA = `sosf-scan/${VERSION} (+security self-check)`;
export const API = 'https://api.github.com';

/** Popularity tiers ("grow with you"). A repo's tier is the higher of its stars tier and dependents tier. */
export const TIERS: { id: number; name: string; stars: number; dependents: number }[] = [
  { id: 0, name: 'Just you', stars: 0, dependents: 0 },
  { id: 1, name: 'First fans', stars: 1, dependents: 1 },
  { id: 2, name: 'Getting noticed', stars: 10, dependents: 5 },
  { id: 3, name: 'Small community', stars: 50, dependents: 25 },
  { id: 4, name: 'Established', stars: 250, dependents: 100 },
  { id: 5, name: 'Widely used', stars: 1000, dependents: 500 },
  { id: 6, name: 'Load-bearing', stars: 5000, dependents: 2500 },
  { id: 7, name: 'Critical infrastructure', stars: 25000, dependents: 10000 },
];

export function tierFor(stars?: number | null, dependents?: number | null): { id: number; name: string } {
  const s = stars || 0;
  const d = dependents || 0;
  let best = TIERS[0];
  for (const t of TIERS) {
    if (s >= t.stars || d >= t.dependents) best = t;
  }
  if (s === 0 && d === 0) best = TIERS[0];
  return { id: best.id, name: best.name };
}

export const RISKY_EXPR = re(
  String.raw`\$\{\{\s*(github\.event\.(issue\.title|issue\.body|pull_request\.title|pull_request\.body|comment\.body|review\.body|` +
    String.raw`review_comment\.body|discussion\.title|discussion\.body|head_commit\.message|head_commit\.author\.(email|name)|` +
    String.raw`pull_request\.head\.ref|pull_request\.head\.label|pages\.[^}]*\.page_name|commits\[?[^}]*\.message|` +
    String.raw`workflow_run\.head_branch|workflow_run\.head_commit\.message)|github\.head_ref)\s*\}\}`,
);

/** CI tools detected in workflow text, in the order the Python dict lists them. Matched case-insensitively. */
export const TOOLS: [string, RegExp][] = (
  [
    ['codeql', String.raw`github/codeql-action/(init|analyze)`],
    ['scorecard', String.raw`ossf/scorecard-action`],
    ['zizmor', String.raw`zizmor`],
    ['actionlint', String.raw`actionlint|poutine`],
    ['dependency_review', String.raw`actions/dependency-review-action`],
    ['harden_runner', String.raw`step-security/harden-runner`],
    [
      'attest',
      String.raw`actions/attest(-build-provenance|-sbom)?@|slsa-framework/slsa-github-generator|--provenance\b`,
    ],
    ['sbom', String.raw`anchore/sbom-action|cyclonedx|\bsyft\b|\bsbom\b`],
    [
      'signing',
      String.raw`sigstore/cosign-installer|cosign\s+sign|sigstore/gh-action-sigstore-python|\bminisign\b|gpg\s+--(detach-sign|armor|sign)|ghaction-import-gpg`,
    ],
    ['pypi_publish', String.raw`pypa/gh-action-pypi-publish|twine upload|uv publish`],
    ['npm_publish', String.raw`\b(npm|pnpm) publish\b|yarn npm publish`],
    ['crates_publish', String.raw`cargo publish|rust-lang/crates-io-auth-action`],
    ['crates_trusted', String.raw`rust-lang/crates-io-auth-action`],
    ['rubygems_publish', String.raw`rubygems/release-gem|gem push\b`],
    ['rubygems_trusted', String.raw`rubygems/release-gem|rubygems/configure-rubygems-credentials`],
    ['goreleaser', String.raw`goreleaser/goreleaser-action|\bgoreleaser release\b`],
    ['gh_release', String.raw`softprops/action-gh-release|\bgh release create\b|ncipollo/release-action`],
    ['docker_push', String.raw`docker/build-push-action|docker push\b`],
    [
      'fuzz',
      String.raw`cifuzz|clusterfuzzlite|cargo\s+(\+\S+\s+)?fuzz|go test[^\n]*-fuzz|\batheris\b|jazzer|libfuzzer`,
    ],
    ['secret_scan', String.raw`gitleaks|trufflehog`],
    ['other_sast', String.raw`semgrep|gosec|\bbandit\b|brakeman|sonarcloud|sonarqube|snyk/actions|njsscan`],
    [
      'dep_audit',
      String.raw`cargo[- ]deny|cargo[- ]audit|rustsec/audit-check|govulncheck|pip-audit|npm audit|osv-scanner|anchore/scan-action|\bgrype\b|trivy`,
    ],
  ] as const
).map(([name, pattern]): [string, RegExp] => [name, re(pattern, 'i')]);

/** The name of each tool the other_sast pattern finds, by what it matched (in lower case). */
export const OTHER_SAST_NAMES: Record<string, string> = {
  semgrep: 'Semgrep',
  gosec: 'gosec',
  bandit: 'Bandit',
  brakeman: 'Brakeman',
  sonarcloud: 'SonarCloud',
  sonarqube: 'SonarQube',
  'snyk/actions': 'Snyk',
  njsscan: 'njsscan',
};

export const PUBLISH_TOOLS = [
  'pypi_publish',
  'npm_publish',
  'crates_publish',
  'rubygems_publish',
  'goreleaser',
  'gh_release',
  'docker_push',
];
export const REGISTRY_TOOLS = ['pypi_publish', 'npm_publish', 'crates_publish', 'rubygems_publish'];
export const TRUSTED_TOOLS = ['pypi_publish', 'npm_publish', 'crates_trusted', 'rubygems_trusted'];

export const FUZZ_PATH = re(
  String.raw`(?i)(^|/)(fuzz|fuzzing|fuzzers|fuzz_targets|fuzztest|oss-fuzz)(/|$)|(^|/)fuzz_[^/]+\.(c|cc|cpp|py|go|rs|java|js|ts)$|` +
    String.raw`[^/]*_fuzz(er)?\.(c|cc|cpp|py|go|rs)$|(^|/)Fuzz[A-Z][^/]*\.(java|kt|scala)$|[^/]*fuzz[^/]*_test\.go$|\.fuzz\.(spec|test)\.[jt]s$`,
);
export const FUZZ_EXCLUDE = re(
  String.raw`(?i)fuzzy|(^|/)(third_party|third-party|vendor|deps|node_modules|external)/|\.gitkeep$`,
);

/** Manifest files and the package ecosystem they belong to, in the Python order. */
export const ECOSYSTEM_FILES: [RegExp, string][] = (
  [
    [String.raw`(^|/)package\.json$`, 'npm'],
    [String.raw`(^|/)(pyproject\.toml|setup\.py|setup\.cfg)$`, 'pypi'],
    [String.raw`(^|/)go\.mod$`, 'go'],
    [String.raw`(^|/)Cargo\.toml$`, 'cargo'],
    [String.raw`(^|/)(pom\.xml|build\.gradle(\.kts)?)$`, 'maven'],
    [String.raw`(^|/)(Gemfile|[^/]+\.gemspec)$`, 'rubygems'],
    [String.raw`(^|/)composer\.json$`, 'composer'],
    [String.raw`\.csproj$`, 'nuget'],
    [String.raw`(^|/)Package\.swift$`, 'swift'],
  ] as const
).map(([pattern, eco]): [RegExp, string] => [re(pattern), eco]);

export const LOCKFILES: Record<string, RegExp> = {
  npm: re(String.raw`(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$`),
  pypi: re(String.raw`(^|/)(uv\.lock|poetry\.lock|Pipfile\.lock|requirements[^/]*\.txt|pdm\.lock)$`),
  go: re(String.raw`(^|/)go\.sum$`),
  cargo: re(String.raw`(^|/)Cargo\.lock$`),
  rubygems: re(String.raw`(^|/)Gemfile\.lock$`),
  composer: re(String.raw`(^|/)composer\.lock$`),
};
