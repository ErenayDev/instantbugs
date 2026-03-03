# InstantBugs

rewritten [dailybugs](https://github.com/ktibow/dailybugs) project from scratch

in dailybugs, the results are sent to you through discord or email once per 24 hours.
but in instantbugs, these are directly in your terminal
analyzes the github repo you give, and sends tons of requests to AI
aand theeen: shows the bugs in your project

> [!important]
> it sends roughly 3-4x more requests to AI than your project file count

first of all, in the beginning, the script pulls all repo files to ram.
then starts sending files to AI one-by-one for analyzing files individually.
after all files are finished, AI links the files to each other and categorizes them. by this way, quality will improve.
after links are finished, again AI analyzes categories with the analyze data it did before.
some files should be uncategorized. these files will fall back to the fallback case. these files will be analyzed in batches (5 files per message)

it uses context7 for getting contexts about the project libraries.

also it has a cache file system. so if you wanna see the bugs you analyzed before again, just run the command again. it will pull the bugs from the .cache folder.

# Installation

```bash
bun install
```

fill .env.template file. then rename it to .env

to run:
```bash
bun run index.ts
```

# Configuration
all configurations can be done through `.env` file.

### REPO_URL (required)
you can pass a branch URL or normal URL. for example:
branch: https://github.com/ErenayDev/checkpoint-ts/tree/develop
normal: https://github.com/ErenayDev/checkpoint-ts
priority: CLI args > .env

### GH_TOKEN (optional, recommended)
github personal access token. increases rate limits. without it, you might hit rate limits on large repos.

### BASE_URL (required)
the base url of ai api proxy. openai-compatible required.
the script auto-fixes the trailing /v1 for cases if you forget to type it
examples: https://example.com/v1 or https://example.com

### API_KEY (required)
api key of the ai api proxy

### MODEL (required)
ai model to be used. it is important that it has reasoning ability (it is better than nothing).

### REASONING_EFFORT
uses it when first analyze
values: low | medium | high
default: medium

### REASONING_EFFORT_FULL
uses it when second, big codebase analyze
values: low | medium | high
default: high

### SHOW_REASONING
shows the reasoning tokens in front of you
values: true | false
default: false

### ENABLE_CONTEXT7 (recommended)
enables context7 capabilities. better than nothing. its free
values: true | false
default: false

### IGNORE_PATTERNS
comma-separated glob patterns to ignore files
example: "*.test.ts,*.spec.js,dist/*"
can also be passed via --ignore CLI flag

### Debug Variables
- DEBUG_CONTEXT7: shows context7 lookup details
- DEBUG_PARSING: shows JSON parsing attempts
- DEBUG_DEPS: shows dependency extraction failures
values: true | false

this project was created using `bun init` in bun v1.3.9. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.
written by [me](https://erenaydev.com.tr)
