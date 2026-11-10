# Privacy

This page explains what sossscan.ntindle.com does with information about you. It's written from the site's code, which is public at [github.com/ntindle/sossscan](https://github.com/ntindle/sossscan), so you can check each statement against it.

The site has no user accounts and no database. There are no analytics, ads or tracking cookies. The page loads nothing from other sites: its content security policy lets it fetch only from sossscan.ntindle.com. When you follow a link to another site, that site sees sossscan.ntindle.com as the referrer, without the rest of the address.

## Public scans

When you scan a repository on the home page, your browser sends the repository's name to this site. The server then reads the repository on GitHub, using a token of the site's own, never yours. Its requests go to:

- GitHub (api.github.com, raw.githubusercontent.com and github.com), for the repository's files, workflows, public settings and dependents;
- the OpenSSF Scorecard API (api.securityscorecards.dev) and the OpenSSF Best Practices badge site (www.bestpractices.dev), which receive the repository's name;
- Anthropic's OSS Scanner project list on GitHub, only for repositories with more than 1,000 stars or 200 dependents.

Whether a repository is in OSS-Fuzz is looked up in a list that ships with the site, so that check sends nothing. All of these requests come from the server and name only the repository. None of them carries your IP address or anything else about you. Private repositories are refused, with the same answer as a repository that doesn't exist.

## Caching

So that a repeat scan doesn't go back to GitHub, the server keeps each public scan's result for 6 hours, in memory and in a cache folder on its disk. The CDN in front of the site keeps the answer from /api/scan/owner/repo for 6 hours too, and for up to 10 minutes longer while it fetches a fresh one. A cached scan describes a public repository and is the same for everyone who asks. Nothing about who asked is stored with it. Rescan skips both caches, and errors, private repositories and scans that GitHub rate-limited are never cached.

## Rate limits

So that one visitor can't use up the site's GitHub quota, the server counts requests per IP address: 6 scans a minute and 40 an hour, and 90 sign-in and app requests a minute. To count them, it keeps your IP address and the times of your recent requests in memory, and never writes them to disk. Request times older than an hour (a minute for sign-in and app requests) are dropped when you make your next request. Addresses that have been quiet for an hour are cleared once the server is tracking more than 20,000, and all of it is gone when the server instance stops.

## Signing in with GitHub

You only need to sign in to use the GitHub App's checks and fixes. The sign-in itself happens on GitHub, under [GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement). When GitHub sends you back, the server gets a GitHub user token for you and asks GitHub for your username.

Both go into a cookie in your browser, with the app's ID and the time your sign-in ends. The cookie is encrypted and signed with a key only the server has, so its contents can't be read or changed in the browser, and the page's scripts can't access it at all. It lasts 7 hours, and Sign out deletes it. While you're on GitHub's sign-in page, a second cookie holds a random value for up to 15 minutes, to make sure the sign-in that comes back started in your browser. These two are the only cookies the site sets.

The server doesn't save your sign-in anywhere. It uses your token for two reads on GitHub: who you are, and whether you're an admin of a repository you ask it to check or fix. It keeps the answer to the second, with whether the app is installed there, in memory and reuses it for up to a minute.

## Checks and fixes through the app

For the app's admin check and for "Fix it for me", the server calls GitHub with a token of the app's installation that covers only that repository. A settings fix is a single API call. A pull request fix is built on the server and shown to you as a preview. The preview comes to your browser encrypted, only you can use it, and it expires after 15 minutes. The pull request opens only when you confirm.

A pull request the app opens is public like any other, and its description says it was opened at your request, with your GitHub username. A new file it adds, such as CODEOWNERS, may also name you as the maintainer. Both are in the preview, so you see them before you confirm.

## AI fixes

AI fixes are turned off on sossscan.ntindle.com. The code supports them for three kinds of workflow problem, through an AI service that the site's operator configures, and none is configured here. If one were, an AI fix you asked for would send that service the problem's description from the guide, the repository's name, what the scan found and the flagged workflow files, plus up to six more files from the repository's .github folder if the model asked for them. It wouldn't send your username, your token or your IP address. The server would keep a monthly total of tokens and cost with no names attached, and your number of AI fixes for the day would be kept in your sign-in cookie.

## In your browser

The page saves a few things in your browser's storage, on your device:

- in localStorage: your theme, the last repository you looked at, the latest public scan of each repository, and the checks you marked done, with any pull request the app opened for them;
- in sessionStorage: reports from the private scan and the GitHub App, which your browser deletes when you close the tab.

Clearing this site's data in your browser removes all of it. The prompts for AI coding agents are built in the page too, and copying one sends nothing.

## The private scan

The [sossscan CLI](/docs/cli) runs on your machine and sends nothing to this site. It reads the repository on GitHub with your token, asks the two OpenSSF services about public repositories, and writes its report to a file on your machine. When you load that file into the page, the page reads it in your browser and keeps it in sessionStorage. It isn't uploaded.

## Hosting

The site runs on Vercel. Vercel receives every request, including your IP address, and keeps logs under its own [privacy notice](https://vercel.com/legal/privacy-policy). The site's own code doesn't log who scans what.

## Questions

Write to [sossscan@ntindle.com](mailto:sossscan@ntindle.com), or see [Contact](/contact) for other ways to reach the maintainer. If this page and the code ever disagree, please [open an issue](https://github.com/ntindle/sossscan/issues/new).

Last updated November 10, 2026.
