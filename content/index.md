# sossscan

sossscan checks a GitHub repository for security gaps and says which one to close first. It follows the stages a change passes on its way to users, from the accounts that can push code to the releases people install, and then the way problems get reported back. Most checks come with what projects in GitHub's Secure Open Source Fund did about the same gap. On the site it's called the Secure Open Source guide. It's free, needs no account, and isn't affiliated with GitHub.

This is the home page as Markdown. The web page at https://sossscan.ntindle.com/ shows the same guide as an interactive map, and needs JavaScript.

## Scan a repository

- In a browser, open `https://sossscan.ntindle.com/?repo=OWNER/REPO`. A github.com address of the repository works too. The page runs the public scan and shows the results.
- From a script or an agent, `GET https://sossscan.ntindle.com/api/scan/OWNER/REPO` returns the report as JSON, with no key or sign-in. The [API docs](/docs/api) describe the report.
- For a private repository, or for settings only admins can see, run the [sossscan CLI](/docs/cli) on your own machine with your own GitHub token.

[sossscan for AI agents](/agents) says when sossscan fits a task, which parts of a report matter and what the limits are.

## Reading a report

A report has one result per check, keyed by the check's id, with a status: `pass`, `warn` (partly in place), `fail`, `info`, `unknown` (this scan couldn't settle it) or `na` (doesn't apply). Problems found in files are listed under `findings`, with the file, the line and a severity.

Each check below says which scan can read it:

- public: the public scan reads it from what anyone can see.
- admin: a setting only the repository's admins can see. A public scan reports it as `unknown`. The CLI with an admin's token, or the [GitHub App](https://github.com/apps/sossscan), checks it.
- self-check: something no scanner can see, such as security training. It isn't in the report. You mark it done on the page.

Each check also has a tier: the size of project at which it's worth doing, from 0, "Just you", to 7, "Critical infrastructure". A repository's tier comes from its stars and dependents. [guide.json](/data/guide.json), about 700 KB, has every check's tier, impact, effort, steps and snippets, under `items`.

## More about sossscan

- [About](/about): where the guide comes from and who made it.
- [Docs](/docs): the API and the CLI.
- [Privacy](/privacy) and [Contact](/contact).
- [llms.txt](/llms.txt): an index of this site for agents.
- The source code is at [github.com/ntindle/sossscan](https://github.com/ntindle/sossscan), under the MIT license.
