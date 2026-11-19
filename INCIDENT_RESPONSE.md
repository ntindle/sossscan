# Incident response plan

What happens when something goes wrong with sossscan: a vulnerability report, a leaked key, a compromised account, a bad deployment, or a fix that harms repositories. It covers the site at https://sossscan.ntindle.com, its API and MCP server, the CLI, and the two GitHub Apps. [SECURITY.md](SECURITY.md) says how to report a problem, and [DEPLOY.md](DEPLOY.md) has the steps for rotating keys and secrets. This is the public version: account recovery details stay private.

## Who responds

- **Incident lead:** Nick Tindle, the maintainer. Reach the maintainer through a private advisory, as SECURITY.md describes, or at sossscan@ntindle.com.
- **Backup:** none yet. sossscan has one maintainer, so a report may wait when the maintainer is away.
- **If you can't reach the maintainer** and think the fix app is being misused, uninstall it from your repositories at https://github.com/settings/installations (for an organization, in its settings under GitHub Apps). That stops it at once. The main app only reads.

## Severity

| Level | What it means | What it triggers |
|---|---|---|
| Critical | Someone can change repositories through the fix app without an admin confirming, the fix app's private key is out, or the deployed site runs code it shouldn't (the server holds every key). | Contain it as soon as the maintainer sees it (playbooks below), then fix it, then publish an advisory that tells users what to check. |
| High | Someone can read what they shouldn't through the site or the apps, such as a private repository's code, a sign-in token or an unpublished advisory; or the main app's key, its client secret or `SOSF_SECRET` is out. | Contain and fix it before any other work on the project. Publish an advisory once it's fixed. |
| Medium | The site or a fix misleads or harms: a check that marks a real gap as done, a fix that breaks a repository's workflows, or abuse that takes the site down. | Fix it in the next change. An advisory if users need to act, otherwise an issue. |
| Low | Hardening, wording, and everything else. | A normal issue or pull request. |

## A vulnerability report

1. Acknowledge it within a week, as SECURITY.md promises, in the advisory's comments.
2. Reproduce it and check that it's in scope. If it isn't, say why and close it.
3. Rate it with the levels above and the advisory's CVSS calculator.
4. Fix it in the advisory's temporary private fork, with a test that fails without the fix.
5. Merge the fix to `main`. That deploys the site, and the next download of the CLI has it.
6. Publish the advisory, crediting the reporter unless they'd rather not be named. Request a CVE when users have to act, such as downloading the CLI again or checking a repository.
7. Ask what would have caught it sooner: a test, a check in the scanner, or a change to this plan.

## Playbooks

### A GitHub App's private key or secret leaks

The fix app's key is the worst case: it can change settings and push code in every repository that has the app installed. DEPLOY.md, under "If a key leaks", lists what each key can do.

1. Stop new tokens first. In the app's settings on GitHub, generate a new key, then delete the leaked one. Fixes stop working until the new key is in Vercel, and that's fine.
2. Put the new key in Vercel and redeploy (DEPLOY.md, "Rotating a private key"). Rotate the client secret and `SOSF_SECRET` too if they may have leaked with it.
3. Find out what the key did. A token made with it lasts up to an hour. Pull requests the fix app opened in public repositories show up in a GitHub search for `is:pr author:app/sossscan-fix`. Settings changes show up only in each repository owner's security log, and the site keeps no list of who used which fix, so the advisory has to ask admins to check.
4. Publish an advisory that says what the key could reach, for how long, and what admins should check.

### A maintainer account is compromised

For the GitHub or the Vercel account:

1. Sign out every other session, and reset the password, passkeys and two-factor recovery codes.
2. Check the account's security log, recent commits and releases, the apps' settings and keys, and Vercel's deployments, domains and environment variables.
3. Undo anything the maintainer didn't do (see "A bad deployment"), rotate every secret the account could see, and contact GitHub Support or Vercel support.

### A bad deployment

For a malicious dependency, a bad commit or a broken build:

1. In Vercel, roll production back to the last good deployment (Instant Rollback).
2. Revert the change on `main`, and check the `package-lock.json` diff for packages that shouldn't be there. `.npmrc` already holds back anything published in the last 7 days.
3. If the bad code could have read the environment, treat every secret as leaked and rotate them all.
4. Report a malicious package to npm.

### A fix that harms repositories

For a settings fix or a pull request template that breaks something:

1. Take the fix off the site, by removing it from `SETTINGS_FIX_PERMISSIONS` in `lib/github-app.ts` or `PR_FIXES` in `lib/fixes.ts`, and deploy.
2. Find the open pull requests it made with a GitHub search for `is:pr is:open author:app/sossscan-fix`, and comment on each with what's wrong and how to fix it.
3. For a settings fix, publish an advisory that says how to change the setting back.

### The site goes down

The CLI keeps working, since it runs on the user's own machine. Check [Vercel's status page](https://www.vercel-status.com) and the project's usage. On the free plan, going over a monthly limit stops the site for 30 days (DEPLOY.md, "Free plan limits"). Then upgrade, or move to the container DEPLOY.md describes.

## Telling people

- An advisory on this repository. People who watch it are notified, and it's where the details go.
- When users must act, a note at the top of the README as well.
- For a problem with a fix, a comment on each pull request the app opened.

## Contacts

- GitHub Support: https://support.github.com
- Vercel support: https://vercel.com/help
- npm, for a malicious package: https://www.npmjs.com/support

Check them whenever the people or services behind the site change.

## Practice

Once a year, open a draft advisory titled DRILL and work through the key leak playbook with a fresh key: generate one, swap it in Vercel, redeploy, and delete the old one. Then close the advisory, which the scanner's `plan-irp-exercise` check counts as a drill, and fix whatever in this plan turned out to be wrong.
