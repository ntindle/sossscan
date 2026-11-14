# Privacy

This page explains what sossscan.ntindle.com does with information about you. It's written from the site's code, which is public at [github.com/ntindle/sossscan](https://github.com/ntindle/sossscan), so you can check each statement against it.

The site has no user accounts and no database. There are no ads or tracking cookies, and the site counts visits without knowing who makes them, as [Counting visits](#counting-visits) explains. The page loads nothing from other sites: its content security policy lets it fetch only from sossscan.ntindle.com. When you follow a link to another site, that site sees sossscan.ntindle.com as the referrer, without the rest of the address.

## Public scans

When you scan a repository on the home page, your browser sends the repository's name to this site. The server then reads the repository on GitHub, using a token of the site's own, never yours. Its requests go to:

- GitHub (api.github.com, raw.githubusercontent.com and github.com), for the repository's files, workflows, languages, releases, open pull requests, closed issues labeled settings-review, public settings and dependents;
- the OpenSSF Scorecard API (api.securityscorecards.dev) and the OpenSSF Best Practices badge site (www.bestpractices.dev), which receive the repository's name;
- Anthropic's OSS Scanner project list on GitHub, only for repositories with more than 1,000 stars or 200 dependents.

Whether a repository is in OSS-Fuzz, or in GitHub's Secure Open Source Fund, is looked up in lists that ship with the site, so those checks send nothing. All of these requests come from the server and name only the repository. None of them carries your IP address or anything else about you. Private repositories are refused, with the same answer as a repository that doesn't exist.

## The MCP server

AI agents can call the site's [MCP server](/docs/mcp). A call sends the server a repository's name or a check's id, along with what the client says about itself, such as its name and version. The server uses them to answer and keeps none of it: there's no session and no log of who called which tool. It counts each call by the tool's name, with nothing about who made it or with what (see [Counting visits](#counting-visits)). A scan through the MCP server is the same public scan as on the home page, and its result is cached the same way.

## Counting visits

To see how the site is used, it counts a few things and sends each count to [PostHog](https://posthog.com), an analytics service in the US. Your browser never talks to PostHog: the page reports to this site, and the server passes each count on, along with the ones it makes itself.

The page counts:

- a page opening: the page's address (such as /docs, without anything after a "?" or "#"), the other site you came from, if any, as its domain only, and whether this is your first visit today, this week and this month;
- a public scan it shows you, a CLI report you open in it, and a prompt for an AI coding agent you copy.

The server counts a scan that a program asks the API for, an MCP tool call with the tool's name, a deep scan, a settings fix with whether GitHub took it, a pull request fix built for you to review and one opened, a sign-in with GitHub, and an installation of the app.

A count is the event's name and those details, nothing more. It carries no IP address, no browser or device details, no cookie, no repository name, no GitHub username, and nothing that links it to another count: each one gets a new random ID, and PostHog keeps no profile of anyone. To tell first visits apart without an ID, the page keeps the day, week and month of your last counted visit in your browser (see [In your browser](#in-your-browser)) and sends only yes or no. Counts reach PostHog from the server's address, never yours. The site asks PostHog not to look up a location, and its PostHog project is set to discard IP addresses.

If your browser sends Do Not Track or Global Privacy Control, nothing is counted, on the page or on the server. Search engines and other crawlers aren't counted, and neither are browsers that programs drive. PostHog keeps the counts under its [privacy policy](https://posthog.com/privacy).

## Caching

So that a repeat scan doesn't go back to GitHub, the server reuses each public scan's result for 6 hours. It keeps the result in memory and in a cache folder on its disk until a newer scan replaces it or the server instance stops. The CDN in front of the site keeps the answer from /api/scan/owner/repo for 6 hours too, and for up to 10 minutes longer while it fetches a fresh one. A cached scan describes a public repository and is the same for everyone who asks. Nothing about who asked is stored with it. Rescan skips both caches. Error responses, private repositories and scans that GitHub rate-limited are never cached.

## Rate limits

So that one visitor can't use up the site's GitHub quota, the server counts requests per IP address: 6 scan requests a minute and 40 an hour, and 90 sign-in and app requests a minute. Requests to the MCP server count too: 120 a minute, and each scan it runs counts as a scan request. The page's counts (see [Counting visits](#counting-visits)) are limited to 60 a minute. To count them, it keeps your IP address and the times of your recent requests in memory, and never writes them to disk. Request times older than an hour (a minute for sign-in, app and MCP requests and the page's counts) are dropped when you make your next request. Addresses that have been quiet for an hour are cleared once the server is tracking more than 20,000, and all of it is gone when the server instance stops.

## Signing in with GitHub

You only need to sign in to use Deep scan and "Fix it for me". The sign-in itself happens on GitHub, under [GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement). When GitHub sends you back, the server gets a GitHub user token for you and asks GitHub for your username.

Both go into a cookie in your browser, with the app's ID and the time your sign-in ends. The cookie is encrypted and signed with a key only the server has, so its contents can't be read or changed in the browser, and the page's scripts can't read it. It lasts 7 hours, and Sign out deletes it. While you're on GitHub's sign-in page, a second cookie holds a random value for up to 15 minutes, to make sure the sign-in that comes back started in your browser. These two are the only cookies the site sets.

The server doesn't save your sign-in anywhere. It uses your token for two reads on GitHub: who you are, and whether you're an admin of the repository you're looking at. When the site's apps are installed there, it keeps that answer in memory, with your username and the repository's name, until the server instance stops, and reuses it for up to a minute.

## Checks and fixes through the apps

The site has two GitHub Apps. Deep scan goes through the main app, sossscan, which can only read. "Fix it for me" goes through the fix app, the only one that can change a repository, which you install only if you want fixes. For each request, the server calls GitHub with a token of that app's installation that covers only that repository and holds only the permissions the request needs. A deep scan runs the whole scan, so for a public repository it also asks the two OpenSSF services about it, as a public scan does. A settings fix is a single API call. A pull request fix is built on the server and shown to you as a preview, with an encrypted copy of the change that only you can use to open the pull request, within 15 minutes. The pull request opens only when you confirm.

Two things Deep scan reads are private, and it keeps neither:

- Private vulnerability reports and other unpublished security advisories. It reads them through the fix app, with a token that can read nothing else, so only where the fix app is installed. It reads how many reports have waited over 14 days with no comment and how old the oldest is, when the last practice advisory titled DRILL was closed, and how many advisories brought in collaborators or have a temporary private fork. None of their text goes into the result: no title, description, reporter or severity.
- The names of the repository's Actions secrets, for the secrets check. GitHub never gives anyone a secret's value, and the result has only how many secrets there are.

The result goes only to your browser, which keeps it for the tab, as below. The server doesn't store it.

A pull request the app opens can be seen by everyone who can see the repository, and its description says it was opened at your request, with your GitHub username. A new file it adds, such as CODEOWNERS, may also name you as the maintainer. Both are in the preview, so you see them before you confirm.

## AI fixes

AI fixes are turned off on sossscan.ntindle.com. The code supports them for three kinds of workflow problem, through an AI service that the site's operator configures, and none is configured here. If one were, an AI fix you asked for would send that service the problem's description from the guide, the repository's name, what the scan found and the flagged workflow files, plus up to six more files from the repository's .github folder if the model asked for them. It wouldn't send your username, your token or your IP address. The server would keep a monthly total of tokens and cost with no names attached, and your number of AI fixes for the day would be kept in your sign-in cookie.

## In your browser

The page saves a few things in your browser's storage, on your device:

- in localStorage: your theme, the last repository you looked at, the latest public scan of each repository, and the checks you marked done and when, with any pull request the app opened for them. The page counts from that date to say when a check that repeats, such as a yearly drill, is due again. It also keeps the day, week and month of your last counted visit, so the next count can say whether it's your first visit of each (see [Counting visits](#counting-visits)), unless your browser sends Do Not Track or Global Privacy Control;
- in sessionStorage, only while you sign in with GitHub or install the app: what you asked for, meaning the repository to deep scan, or the check whose fix you had open, with its repository and the time. The page deletes it the next time it loads, and after 15 minutes it isn't used.

Reports from deep scans, and reports from the CLI when its token had admin access, aren't saved anywhere. They stay in the open page's memory only, so reloading or closing the page clears them, and you scan again to see them.

A report from the CLI without admin access is marked as a public scan, so the page keeps it in localStorage in place of the public scan of that repository. Clearing this site's data in your browser removes all of it. The prompts for AI coding agents are built in the page too, and copying one sends nothing.

## The private scan

The [sossscan CLI](/docs/cli) runs on your machine and sends nothing to this site. It reads the repository on GitHub with your token, asks the two OpenSSF services about public repositories, and writes its report to a file on your machine. With an admin's token it reads unpublished advisories and secret names as Deep scan does, and its report has the same counts and dates, nothing more. When you load that file into the page, the page reads it in your browser and keeps it as described above. It isn't uploaded. If you're signed in with GitHub, the page does send the repository's name, though not the report, to ask whether you're an admin there.

## Hosting

The site runs on Vercel. Vercel receives every request, including your IP address, and keeps logs under its own [privacy notice](https://vercel.com/legal/privacy-policy). The site's own code doesn't log who scans what: its counts name no person and no repository.

## Questions

Write to [sossscan@ntindle.com](mailto:sossscan@ntindle.com), or see [Contact](/contact) for other ways to reach the maintainer. If this page and the code ever disagree, please [open an issue](https://github.com/ntindle/sossscan/issues/new).

Last updated November 13, 2026.
