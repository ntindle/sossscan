# About sossscan

sossscan is a security scanner and guide for open source maintainers. Give it a GitHub repository and it shows where the project has security gaps, from the accounts that can push code to the releases your users install, and which gap to close first. Most checks come with what projects in GitHub's Secure Open Source Fund did about the same problem: what they wrote about it and, where there are any, the files they added and the commits that fixed it. On the site it's called the Secure Open Source guide.

## What it checks

The guide has 81 checks, in the order a change meets them on its way to your users: accounts, repository settings, code, pull requests and CI, dependencies, and build and release. Three more stages follow the way problems come back to you: disclosure, response, and the people on the project.

The public scan covers 36 of the checks, using what anyone can see, and a scan with admin access covers 10 more. The other 35 are things no scanner can see, such as security training or an incident plan you've rehearsed, so you mark those done yourself.

Each check also has a tier: the size of project at which it's worth doing, from "Just you" to "Critical infrastructure". Your repository's tier comes from its stars and dependents, and checks above it wait in a list called "Later, as you grow".

For each check a scan reads, you get a status and its findings, with file and line. Every check has steps to follow yourself. Most also have a prompt to paste into your AI coding agent, and some can be fixed by the GitHub App, which changes a setting in one click or opens a pull request that you preview first.

## Where the guide comes from

The guide is built from what the 193 projects in the Fund wrote and changed. Their 84 posts and GitHub's write-ups about the program give 784 quoted statements about what a team did, planned or recommends. A scan of each project's repository adds the controls it has and the commits where teams fixed CI and supply chain risks.

The research files stay private because they hold full copies of the original posts. What's published is the result, [guide.json](/data/guide.json), with short quotes that link to their sources.

The repository checks are heuristics that read file names and workflow text, so treat a finding as a lead to verify. The README lists the [known limitations](https://github.com/ntindle/sossscan#known-limitations).

## Three ways to scan

The public scan runs on this site. Type owner/repo on the [home page](/) and the server reads what anyone can see: files, workflows, public settings, and whether the project has an OpenSSF Scorecard, a Best Practices badge or an OSS-Fuzz project. For larger projects it also checks for an OSS Scanner enrollment. It only reads, and it refuses private repositories. Results are cached for 6 hours. Scripts can run the same scan through the [sossscan API](/docs/api).

The private scan runs on your machine. Download the [sossscan CLI](/docs/cli), run it with Node.js and your own GitHub token, then load the JSON report it writes into the page. With a token that has admin access, it also checks settings only admins can see, such as secret scanning and Dependabot alerts. The page reads the report in your browser and doesn't upload it.

The [GitHub App](https://github.com/apps/sossscan) checks the same admin settings from the site, once you install it on a repository and sign in. It can also fix some of them: nine settings in one click, and pull requests that add a missing file such as SECURITY.md or pin your actions to commit SHAs. You see each change before it's made. The app never merges anything and never pushes to an existing branch.

## Who made it

sossscan was made by [Nick Tindle](https://ntindle.com) ([ntindle on GitHub](https://github.com/ntindle)), a maintainer of AutoGPT, which took part in the Fund's first session.

The code is open source under the MIT license, at [github.com/ntindle/sossscan](https://github.com/ntindle/sossscan).

sossscan is an independent project. It isn't affiliated with GitHub, and GitHub hasn't endorsed it.
