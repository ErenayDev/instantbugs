import normalizeUrl from "normalize-url";
import { existsSync, mkdirSync } from "fs";
import { join } from "path";
import chalk from "chalk";
import { cpus } from "os";
import ora, { type Ora } from "ora";
import { extractJsonFromString, jsonParser } from "extract-json-from-string-y";
import { minimatch } from "minimatch";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { Context7 } from "@upstash/context7-sdk";

const argv = await yargs(hideBin(process.argv))
  .option("repo", {
    alias: "r",
    type: "string",
    description: "GitHub repository URL",
    demandOption: false,
  })
  .option("ignore", {
    alias: "i",
    type: "array",
    description: "Patterns to ignore (glob syntax)",
    default: [],
  })
  .help()
  .parse();

const REPO_URL = argv.repo || Bun.env.REPO_URL;
if (!REPO_URL) {
  console.error(
    chalk.red(
      "Error: Repository URL is required. Use --repo flag or set REPO_URL environment variable.",
    ),
  );
  process.exit(1);
}

const BASE_URL = Bun.env.BASE_URL;
const API_KEY = Bun.env.API_KEY;
const MODEL = Bun.env.MODEL;

if (!BASE_URL || !API_KEY || !MODEL) {
  console.error(
    chalk.red(
      "Error: BASE_URL, API_KEY, and MODEL environment variables are required.",
    ),
  );
  process.exit(1);
}

const IGNORE_PATTERNS = [
  ...(argv.ignore as string[]),
  ...(Bun.env.IGNORE_PATTERNS?.split(",") || []),
];
const FILES_PER_BATCH = 5;
const MAX_FILE_SIZE = 100000;
const CPU_COUNT = cpus().length;
const REASONING_EFFORT = Bun.env.REASONING_EFFORT || "medium";
const REASONING_EFFORT_FULL = Bun.env.REASONING_EFFORT_FULL || "high";
const ENABLE_CONTEXT7 = Bun.env.ENABLE_CONTEXT7 === "true";

let context7Client: Context7 | null = null;
if (ENABLE_CONTEXT7) {
  try {
    context7Client = new Context7();
  } catch (error) {
    console.log(
      chalk.yellow(
        "Failed to initialize Context7 client, disabling Context7 feature",
      ),
    );
  }
}

const fixBaseURL = (baseURL: string) => {
  const url = normalizeUrl(baseURL);
  return url.endsWith("/v1") ? url : `${url}/v1`;
};

type FileEntry = {
  path: string;
  sha: string;
  content: string;
  analyzed: boolean;
};

type FileDependencies = {
  imports: string[];
  exports: string[];
  relatedFiles: string[];
};

type FileAnalysisResult = {
  file: FileEntry;
  bugs: BugData[];
  dependencies: FileDependencies;
};

type CacheData = {
  lastCommit: string;
  branch: string;
  files: Record<string, FileEntry>;
  timestamp: number;
};

type Severity = "MAJOR" | "MEDIUM" | "CVE" | "MINOR" | "UNKNOWN";

type CVEInfo = {
  score: number;
  affected: string[];
  description: string;
};

type BugData = {
  path: string;
  description: string;
  severity: Severity;
  diff: string;
  reasoning?: string;
  cve?: CVEInfo;
};

type TreeItem = {
  path: string;
  mode: string;
  type: string;
  sha: string;
  size?: number;
  url: string;
};

type TreeResponse = {
  sha: string;
  url: string;
  tree: TreeItem[];
  truncated: boolean;
};

type DependencyGraph = {
  [filePath: string]: FileDependencies;
};

type StrategicBatch = {
  reason: string;
  files: string[];
};

const SEVERITY_COLORS: Record<Severity, chalk.Chalk> = {
  MAJOR: chalk.bold.red,
  MEDIUM: chalk.hex("#FFA500"),
  CVE: chalk.hex("#8B0000").bold,
  MINOR: chalk.blue,
  UNKNOWN: chalk.gray,
};

const SYSTEM_PROMPT = `You are an expert code analyzer. Key behaviors:
1. Tone: Direct, technical, no fluff
2. Confidence: Only report bugs you're 90%+ certain about
3. Formatting: Minimal - only use structure when essential
4. Reasoning: Think step-by-step before concluding

When analyzing code:
- Assume the developer is competent
- Don't report style issues or potential edge cases
- Focus on runtime failures in normal execution
- Validate your findings before reporting`;

const ANALYSIS_INSTRUCTIONS = `Analyze the following code files for finding the bugs.

Task:
Identify bugs that will cause the code to fail in normal execution flow.

Calibration:
- Confidence threshold:
    - MAJOR: 90%+ If you'd use words like "might", "could", or "if", don't report as MAJOR.
    - MEDIUM: 75%+
    - CVE: Security vulnerabilities (injection, XSS, auth bypass, etc.)
    - MINOR: 35%+
    - UNKNOWN: use for unknown cases

What is a bug:
- Logic errors: inverted conditions, wrong operators, off-by-one errors, infinite loops
- Async flow failures: missing await when value is needed, awaiting non-promises
- Type mismatches: incorrect type usage that breaks runtime
- Reference errors: undefined variables, accessing undefined properties
- Control flow bugs: unreachable code, incorrect branching
- Security vulnerabilities: SQL injection, XSS, authentication bypass, path traversal, etc.

What is NOT a bug:
- Style issues, missing documentation
- Potential edge cases without proof of failure
- Missing error handling unless it causes immediate crash
- Architecture suggestions

${
  ENABLE_CONTEXT7
    ? `
Documentation Lookup:
When uncertain about technical details (syntax, features, versions, APIs), request documentation:
<need_docs>library_name: your search query here</need_docs>

Examples:
- <need_docs>rust: edition 2024</need_docs>
- <need_docs>clap: derive macro version 4.5</need_docs>
- <need_docs>svelte: runes syntax</need_docs>

Documentation will be provided automatically. Continue analysis after receiving it.
IMPORTANT: Only request docs when confidence < 95%. Don't request for obvious things.
`
    : ""
}

Context:
- Today is ${new Date().toLocaleDateString()}

Output format:
You MUST provide valid JSON. Think carefully, then output ONLY the JSON array.
Wrap your JSON response in a code block with the dailybugs language identifier:

\`\`\`dailybugs
[
  {
    "path": "file/path.ts",
    "description": "clear bug description",
    "severity": "MAJOR | MEDIUM | CVE | MINOR | UNKNOWN",
    "diff": "--- a/file\\n+++ b/file\\n-old line\\n+new line",
    "cve": {
      "score": 8.5,
      "affected": ["authentication", "data integrity"],
      "description": "SQL injection vulnerability allows attackers to bypass authentication"
    }
  }
]
\`\`\`

CRITICAL:
- Every bug object MUST have: path, description, severity, and diff.
- CVE severity bugs MUST include cve object with score (0-10), affected areas, and description.
- If diff is not applicable, use "N/A" as the value.

Return empty array if no bugs found:
\`\`\`dailybugs
[]
\`\`\``;

const DEPENDENCY_EXTRACTION_PROMPT = `Analyze this file and extract its dependencies.

File: {filePath}
Content:
\`\`\`
{fileContent}
\`\`\`

Task:
Extract all file imports/dependencies from this code. Focus on LOCAL files only (not npm packages or standard library).

Output format (JSON):
\`\`\`json
{
  "imports": ["relative/path/to/file.ts", "another/file.js"],
  "exports": ["functionName", "ClassName"],
  "relatedFiles": ["files/that/might/use/this.ts"]
}
\`\`\`

Rules:
- imports: Local file paths this file imports FROM (e.g., "./utils.ts", "../lib/db.js")
- exports: Named exports this file provides (functions, classes, constants)
- relatedFiles: Files that likely import THIS file (based on exports and file purpose)
- Normalize paths (remove ./, ../, file extensions if ambiguous)
- Return empty arrays if none found
- DO NOT include npm packages or standard library imports

Output ONLY the JSON, no explanations.`;

const BATCH_STRATEGY_PROMPT = `Given this codebase dependency graph, create strategic analysis batches.

Dependency Graph:
{dependencyGraph}

Task:
Group related files into batches for cross-file bug analysis.

Rules:
- Group files that import each other
- Group API routes with their services/utils/models
- Group components with their hooks/contexts
- Max 5 files per batch
- Prioritize high-coupling files (many imports/exports)
- Each file should appear in at most one batch
- Create 3-8 batches total

Output format (JSON):
\`\`\`json
[
  {
    "reason": "Auth flow - route + JWT + user service",
    "files": ["routes/auth.ts", "lib/jwt.ts", "services/user.ts"]
  },
  {
    "reason": "Database layer - models + queries",
    "files": ["models/user.ts", "lib/db.ts", "lib/query.ts"]
  }
]
\`\`\`

Output ONLY the JSON array, no explanations.`;

const shouldIgnoreFile = (filePath: string): boolean => {
  return IGNORE_PATTERNS.some((pattern) => minimatch(filePath, pattern));
};

const getCacheDir = (
  repoUrl: string,
): { cacheDir: string; cacheFile: string; bugFile: string } => {
  const { owner, repo } = parseRepoURL(repoUrl);
  const cacheDir = join(process.cwd(), ".cache", "dailybugs", owner, repo);
  const cacheFile = join(cacheDir, "codebase.json");
  const bugFile = join(cacheDir, "bugs.json");
  return { cacheDir, cacheFile, bugFile };
};

const parseRepoURL = (
  url: string,
): { owner: string; repo: string; branch?: string } => {
  const cleanURL = url.replace("https://github.com/", "");
  const parts = cleanURL.split("/");
  if (parts.length < 2) {
    throw new Error("Invalid repository URL");
  }
  const owner = parts[0];
  const repo = parts[1];
  let branch: string | undefined = undefined;
  if (parts.length >= 4 && parts[2] === "tree") {
    branch = parts.slice(3).join("/");
  }
  return { owner, repo, branch };
};

const fetchDefaultBranch = async (
  owner: string,
  repo: string,
): Promise<string> => {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}`,
    {
      headers: getGitHubHeaders(),
    },
  );
  if (!response.ok) {
    throw new Error(
      `GitHub API error: ${response.status} ${await response.text()}`,
    );
  }
  const data = await response.json();
  return data.default_branch;
};

const getGitHubHeaders = () => {
  const headers: Record<string, string> = {
    accept: "application/vnd.github.v3+json",
    "user-agent": "DailyBugs",
  };
  if (Bun.env.GH_TOKEN) {
    headers.authorization = `Bearer ${Bun.env.GH_TOKEN}`;
  }
  return headers;
};

const validateBugData = (bug: any): bug is BugData => {
  if (typeof bug !== "object" || bug === null) return false;
  if (typeof bug.path !== "string" || bug.path.length === 0) return false;
  if (typeof bug.description !== "string" || bug.description.length === 0)
    return false;
  if (typeof bug.severity !== "string") return false;
  if (typeof bug.diff !== "string") return false;
  if (bug.severity === "CVE") {
    if (!bug.cve || typeof bug.cve !== "object") return false;
    if (
      typeof bug.cve.score !== "number" ||
      bug.cve.score < 0 ||
      bug.cve.score > 10
    )
      return false;
    if (!Array.isArray(bug.cve.affected) || bug.cve.affected.length === 0)
      return false;
    if (
      typeof bug.cve.description !== "string" ||
      bug.cve.description.length === 0
    )
      return false;
  }
  return true;
};

const loadCache = async (cacheFile: string): Promise<CacheData | null> => {
  if (!existsSync(cacheFile)) return null;
  try {
    const data = Bun.file(cacheFile, { type: "application/json" });
    return await data.json();
  } catch (e) {
    console.error(e);
    return null;
  }
};

const loadBugs = async (bugFile: string): Promise<BugData[]> => {
  if (!existsSync(bugFile)) return [];
  try {
    const data = Bun.file(bugFile, { type: "application/json" });
    const bugs = await data.json();
    if (!Array.isArray(bugs)) return [];
    return bugs.filter(validateBugData);
  } catch (e) {
    console.error(e);
    return [];
  }
};

const saveCache = async (
  cacheFile: string,
  cacheDir: string,
  cache: CacheData,
): Promise<void> => {
  if (!existsSync(cacheDir)) {
    mkdirSync(cacheDir, { recursive: true });
  }
  await Bun.write(cacheFile, JSON.stringify(cache));
};

const saveBugs = async (
  bugFile: string,
  cacheDir: string,
  bugs: BugData[],
): Promise<void> => {
  if (!existsSync(cacheDir)) {
    mkdirSync(cacheDir, { recursive: true });
  }
  const validBugs = bugs.filter(validateBugData);
  await Bun.write(bugFile, JSON.stringify(validBugs, null, 2));
};

const fetchRepoTree = async (
  owner: string,
  repo: string,
  branch: string,
): Promise<TreeItem[]> => {
  const branchResponse = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/branches/${branch}`,
    {
      headers: getGitHubHeaders(),
    },
  );
  if (!branchResponse.ok) {
    throw new Error(
      `GitHub branch API error: ${branchResponse.status} ${await branchResponse.text()}`,
    );
  }
  const branchData = await branchResponse.json();
  const sha = branchData.commit.sha;
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${sha}?recursive=1`,
    {
      headers: getGitHubHeaders(),
    },
  );
  if (!response.ok) {
    throw new Error(
      `GitHub tree API error: ${response.status} ${await response.text()}`,
    );
  }
  const data = (await response.json()) as TreeResponse;
  return data.tree.filter(
    (item) =>
      item.type === "blob" &&
      !item.path.match(
        /\.(lock|min\.js|map|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$/,
      ) &&
      !shouldIgnoreFile(item.path),
  );
};

const fetchFileContent = async (
  owner: string,
  repo: string,
  path: string,
  branch: string,
): Promise<string> => {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${branch}`,
    {
      headers: {
        ...getGitHubHeaders(),
        accept: "application/vnd.github.v3.raw",
      },
    },
  );
  if (!response.ok) {
    throw new Error(`GitHub content API error: ${response.status}`);
  }
  return await response.text();
};

const fetchLatestCommit = async (
  owner: string,
  repo: string,
  branch: string,
): Promise<string> => {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/commits?sha=${branch}&per_page=1`,
    {
      headers: getGitHubHeaders(),
    },
  );
  if (!response.ok) {
    throw new Error(`GitHub commits API error: ${response.status}`);
  }
  const data = await response.json();
  return data[0].sha;
};

const context7Cache = new Map<string, string>();

const searchContext7 = async (
  libraryName: string,
  query: string,
): Promise<string> => {
  if (!context7Client) {
    return `\n[Context7 not available]`;
  }
  const cacheKey = `${libraryName}:${query}`;
  if (context7Cache.has(cacheKey)) {
    if (Bun.env.DEBUG_CONTEXT7 === "true") {
      console.log(chalk.cyan(`\n[Context7] Cache hit for: ${cacheKey}`));
    }
    return context7Cache.get(cacheKey)!;
  }
  try {
    if (Bun.env.DEBUG_CONTEXT7 === "true") {
      console.log(chalk.cyan(`\n[Context7] Searching library: ${libraryName}`));
    }
    const libraries = await context7Client.searchLibrary(query, libraryName);
    if (libraries.length === 0) {
      const result = `[No library found for: ${libraryName}]`;
      context7Cache.set(cacheKey, result);
      return result;
    }
    const library = libraries[0];
    if (Bun.env.DEBUG_CONTEXT7 === "true") {
      console.log(
        chalk.cyan(
          `\n[Context7] Found library: ${library.name} (${library.id})`,
        ),
      );
    }
    const context = await context7Client.getContext(query, library.id, {
      type: "txt",
    });
    const result = context.slice(0, 3000);
    context7Cache.set(cacheKey, result);
    return result;
  } catch (error) {
    console.log(chalk.yellow(`\n[Context7] Error: ${error}`));
    return `[Documentation lookup failed for: ${libraryName}]`;
  }
};

const extractJSON = (content: string): any[] => {
  try {
    const extracted = extractJsonFromString(content, jsonParser);
    if (extracted.length > 0) {
      const result = Array.isArray(extracted[0]) ? extracted[0] : extracted;
      return result;
    }
  } catch (error) {
    if (Bun.env.DEBUG_PARSING === "true") {
      console.log(
        chalk.red("\nFailed to parse JSON with extract-json-from-string-y"),
      );
      console.log(chalk.gray(content));
    }
  }
  const codeBlockMatch = content.match(/```(?:json|dailybugs)\s*([\s\S]*?)```/);
  if (codeBlockMatch) {
    try {
      return JSON.parse(codeBlockMatch[1].trim());
    } catch (error) {
      if (Bun.env.DEBUG_PARSING === "true") {
        console.log(chalk.red("Failed to parse JSON from code block"));
        console.log(chalk.gray(codeBlockMatch[1]));
      }
    }
  }
  const jsonArrayMatch = content.match(/\[[\s\S]*?\]/);
  if (jsonArrayMatch) {
    try {
      return JSON.parse(jsonArrayMatch[0]);
    } catch (error) {
      if (Bun.env.DEBUG_PARSING === "true") {
        console.log(chalk.red("Failed to parse JSON array"));
        console.log(chalk.gray(jsonArrayMatch[0]));
      }
    }
  }
  return [];
};

const extractJSONObject = (content: string): any => {
  try {
    const extracted = extractJsonFromString(content, jsonParser);
    if (extracted.length > 0) {
      return extracted[0];
    }
  } catch (error) {
    if (Bun.env.DEBUG_PARSING === "true") {
      console.log(chalk.red("\nFailed to parse JSON object"));
    }
  }
  const codeBlockMatch = content.match(/```(?:json)\s*([\s\S]*?)```/);
  if (codeBlockMatch) {
    try {
      return JSON.parse(codeBlockMatch[1].trim());
    } catch (error) {
      if (Bun.env.DEBUG_PARSING === "true") {
        console.log(chalk.red("Failed to parse JSON from code block"));
      }
    }
  }
  const jsonMatch = content.match(/\{[\s\S]*\}/);
  if (jsonMatch) {
    try {
      return JSON.parse(jsonMatch[0]);
    } catch (error) {
      if (Bun.env.DEBUG_PARSING === "true") {
        console.log(chalk.red("Failed to parse JSON object"));
      }
    }
  }
  return null;
};

const callAIWithDocs = async (
  messages: Array<{ role: string; content: string }>,
  reasoningEffort: string,
  maxIterations: number = 3,
): Promise<{ content: string; reasoning?: string }> => {
  if (!ENABLE_CONTEXT7) {
    const response = await fetch(fixBaseURL(BASE_URL) + "/chat/completions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: MODEL,
        messages,
        stream: false,
        reasoning: {
          effort: reasoningEffort,
          exclude: false,
        },
      }),
    });
    if (!response.ok) {
      throw new Error(`AI error: ${response.status} ${await response.text()}`);
    }
    const { choices } = (await response.json()) as any;
    const message = choices[0].message;
    return {
      content: message.content,
      reasoning: message.reasoning || message.reasoning_content || null,
    };
  }
  const seenQueries = new Set<string>();
  for (let iterations = 0; iterations < maxIterations; iterations++) {
    const response = await fetch(fixBaseURL(BASE_URL) + "/chat/completions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: MODEL,
        messages,
        stream: false,
        reasoning: {
          effort: reasoningEffort,
          exclude: false,
        },
      }),
    });
    if (!response.ok) {
      throw new Error(`AI error: ${response.status} ${await response.text()}`);
    }
    const { choices } = (await response.json()) as any;
    const message = choices[0].message;
    const reasoning = message.reasoning || message.reasoning_content || null;
    const docsNeeded = message.content.match(
      /<need_docs>([^:]+):\s*(.*?)<\/need_docs>/g,
    );
    if (!docsNeeded) {
      return { content: message.content, reasoning };
    }
    const queries = docsNeeded
      .map((tag) => {
        const match = tag.match(/<need_docs>([^:]+):\s*(.*?)<\/need_docs>/);
        if (match) {
          return { library: match[1].trim(), query: match[2].trim() };
        }
        return null;
      })
      .filter(Boolean) as { library: string; query: string }[];
    const newQueries = queries.filter((q) => {
      const key = `${q.library}:${q.query}`;
      if (seenQueries.has(key)) return false;
      seenQueries.add(key);
      return true;
    });
    if (newQueries.length === 0) {
      if (Bun.env.DEBUG_CONTEXT7 === "true") {
        console.log(
          chalk.yellow(
            "\n[Context7] AI keeps requesting same docs, breaking loop",
          ),
        );
      }
      return { content: message.content, reasoning };
    }
    if (Bun.env.DEBUG_CONTEXT7 === "true") {
      console.log(
        chalk.cyan(
          `\n[Context7] Fetching docs for ${newQueries.length} queries`,
        ),
      );
    }
    const docsResults = await Promise.all(
      newQueries.map((q) => searchContext7(q.library, q.query)),
    );
    const originalUserMessage = messages[messages.length - 1];
    let newContent = originalUserMessage.content;
    newQueries.forEach((query, i) => {
      const docs = `\n\n[Documentation for "${query.library}: ${query.query}"]\n${docsResults[i]}\n`;
      newContent += docs;
    });
    messages = [
      ...messages.slice(0, -1),
      {
        role: "user",
        content: newContent,
      },
    ];
    if (Bun.env.DEBUG_CONTEXT7 === "true") {
      console.log(
        chalk.cyan(
          `\n[Context7] Re-analyzing with docs (iteration ${iterations + 1})`,
        ),
      );
    }
  }
  if (Bun.env.DEBUG_CONTEXT7 === "true") {
    console.log(
      chalk.yellow(
        "\n[Context7] Max iterations reached, returning last response",
      ),
    );
  }
  const finalResponse = await fetch(
    fixBaseURL(BASE_URL) + "/chat/completions",
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: MODEL,
        messages,
        stream: false,
        reasoning: {
          effort: reasoningEffort,
          exclude: false,
        },
      }),
    },
  );
  if (!finalResponse.ok) {
    throw new Error(
      `AI error: ${finalResponse.status} ${await finalResponse.text()}`,
    );
  }
  const { choices } = (await finalResponse.json()) as any;
  const message = choices[0].message;
  return {
    content: message.content.replace(/<need_docs>.*?<\/need_docs>/g, "").trim(),
    reasoning: message.reasoning || message.reasoning_content || null,
  };
};

const extractDependencies = async (
  file: FileEntry,
): Promise<FileDependencies> => {
  try {
    const prompt = DEPENDENCY_EXTRACTION_PROMPT.replace(
      "{filePath}",
      file.path,
    ).replace("{fileContent}", file.content.slice(0, 5000));
    const response = await fetch(fixBaseURL(BASE_URL) + "/chat/completions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: "user", content: prompt }],
        stream: false,
        temperature: 0.3,
      }),
    });
    if (!response.ok) {
      throw new Error(`AI error: ${response.status}`);
    }
    const { choices } = (await response.json()) as any;
    const result = extractJSONObject(choices[0].message.content);
    if (!result) {
      return { imports: [], exports: [], relatedFiles: [] };
    }
    return {
      imports: Array.isArray(result.imports) ? result.imports : [],
      exports: Array.isArray(result.exports) ? result.exports : [],
      relatedFiles: Array.isArray(result.relatedFiles)
        ? result.relatedFiles
        : [],
    };
  } catch (error) {
    if (Bun.env.DEBUG_DEPS === "true") {
      console.log(
        chalk.yellow(
          `Failed to extract dependencies for ${file.path}: ${error}`,
        ),
      );
    }
    return { imports: [], exports: [], relatedFiles: [] };
  }
};

const createStrategicBatches = async (
  graph: DependencyGraph,
  allFiles: FileEntry[],
): Promise<StrategicBatch[]> => {
  try {
    const graphSummary = Object.entries(graph)
      .map(([path, deps]) => ({
        file: path,
        imports: deps.imports.slice(0, 5),
        exports: deps.exports.slice(0, 5),
      }))
      .slice(0, 100);
    const prompt = BATCH_STRATEGY_PROMPT.replace(
      "{dependencyGraph}",
      JSON.stringify(graphSummary, null, 2),
    );
    const response = await fetch(fixBaseURL(BASE_URL) + "/chat/completions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: MODEL,
        messages: [{ role: "user", content: prompt }],
        stream: false,
        temperature: 0.5,
      }),
    });
    if (!response.ok) {
      throw new Error(`AI error: ${response.status}`);
    }
    const { choices } = (await response.json()) as any;
    const batches = extractJSON(choices[0].message.content);
    if (!Array.isArray(batches) || batches.length === 0) {
      throw new Error("Invalid batch strategy response");
    }
    return batches
      .filter((b) => b.reason && Array.isArray(b.files) && b.files.length > 0)
      .map((b) => ({
        reason: b.reason,
        files: b.files.slice(0, 5),
      }));
  } catch (error) {
    console.log(chalk.yellow(`Failed to create strategic batches: ${error}`));
    return [];
  }
};

const analyzeSingleFile = async (
  file: FileEntry,
  useSystemPrompt: boolean,
  reasoningEffort: string,
): Promise<BugData[]> => {
  const fileContent = `### ${file.path}\n\`\`\`\n${file.content}\n\`\`\``;
  let messages: Array<{ role: string; content: string }>;
  if (useSystemPrompt) {
    messages = [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `${ANALYSIS_INSTRUCTIONS}\n\n${fileContent}` },
    ];
  } else {
    messages = [
      {
        role: "user",
        content: `${SYSTEM_PROMPT}\n\n${ANALYSIS_INSTRUCTIONS}\n\n${fileContent}`,
      },
    ];
  }
  const { content, reasoning } = await callAIWithDocs(
    messages,
    reasoningEffort,
  );
  const extractedBugs = extractJSON(content);
  const validBugs = extractedBugs.filter(validateBugData);
  const bugs = validBugs.map((bug) => ({
    path: bug.path,
    description: bug.description,
    severity: (bug.severity?.toUpperCase() || "UNKNOWN") as Severity,
    diff: bug.diff || "N/A",
    reasoning: reasoning ? reasoning.slice(0, 500) : undefined,
    cve: bug.cve,
  }));
  return bugs;
};

const analyzeFileBatch = async (
  files: FileEntry[],
  conversationHistory: Array<{ role: string; content: string }>,
  useSystemPrompt: boolean,
  reasoningEffort: string,
): Promise<{
  bugs: BugData[];
  history: Array<{ role: string; content: string }>;
}> => {
  const filesContent = files
    .map((file) => `### ${file.path}\n\`\`\`\n${file.content}\n\`\`\``)
    .join("\n\n");
  let messages: Array<{ role: string; content: string }>;
  if (useSystemPrompt) {
    messages = [
      { role: "system", content: SYSTEM_PROMPT },
      ...conversationHistory,
      { role: "user", content: `${ANALYSIS_INSTRUCTIONS}\n\n${filesContent}` },
    ];
  } else {
    messages = [
      ...conversationHistory,
      {
        role: "user",
        content: `${SYSTEM_PROMPT}\n\n${ANALYSIS_INSTRUCTIONS}\n\n${filesContent}`,
      },
    ];
  }
  const { content, reasoning } = await callAIWithDocs(
    messages,
    reasoningEffort,
  );
  const updatedHistory = [
    ...conversationHistory,
    {
      role: "user",
      content: useSystemPrompt
        ? `${ANALYSIS_INSTRUCTIONS}\n\n${filesContent}`
        : messages[messages.length - 1].content,
    },
    { role: "assistant", content },
  ];
  const extractedBugs = extractJSON(content);
  const validBugs = extractedBugs.filter(validateBugData);
  const bugs = validBugs.map((bug) => ({
    path: bug.path,
    description: bug.description,
    severity: (bug.severity?.toUpperCase() || "UNKNOWN") as Severity,
    diff: bug.diff || "N/A",
    reasoning: reasoning ? reasoning.slice(0, 500) : undefined,
    cve: bug.cve,
  }));
  return { bugs, history: updatedHistory };
};

const chunkArray = <T>(array: T[], size: number): T[][] => {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
};

const renderDiff = (text: string) => {
  if (!text || typeof text !== "string" || text === "N/A") {
    return chalk.gray("(no diff provided)");
  }
  return text
    .split("\n")
    .map((line) => {
      if (line.startsWith("+")) return chalk.green(line);
      if (line.startsWith("-")) return chalk.red(line);
      return line;
    })
    .join("\n");
};

const processInParallelWithSpinner = async <T, R>(
  items: T[],
  processor: (item: T, index: number) => Promise<R>,
  spinner: Ora,
  spinnerPrefix: string,
  maxConcurrent: number = CPU_COUNT,
): Promise<R[]> => {
  const results: R[] = [];
  let completed = 0;
  const total = items.length;
  const processItem = async (item: T, globalIndex: number): Promise<R> => {
    const result = await processor(item, globalIndex);
    completed++;
    spinner.text = chalk.magenta(`${spinnerPrefix} [${completed}/${total}]`);
    return result;
  };
  const chunks = chunkArray(items, maxConcurrent);
  for (const chunk of chunks) {
    const chunkResults = await Promise.all(
      chunk.map((item, i) => {
        const globalIndex = results.length + i;
        return processItem(item, globalIndex);
      }),
    );
    results.push(...chunkResults);
  }
  return results;
};

const deduplicateBugs = (bugs: BugData[]): BugData[] => {
  return Array.from(
    new Map(bugs.map((b) => [`${b.path}:${b.description}`, b])).values(),
  );
};

const printBugs = async (
  allBugs: BugData[],
  owner: string,
  repo: string,
  latestCommit: string,
  bugFile: string,
  cacheDir: string,
): Promise<void> => {
  if (allBugs.length === 0) {
    const existingBugs = await loadBugs(bugFile);
    if (existingBugs.length === 0) {
      console.log(chalk.green("no bugs found."));
      return;
    }
    allBugs = existingBugs;
  }
  const validBugs = allBugs.filter(validateBugData);
  if (validBugs.length === 0) {
    console.log(chalk.green("no valid bugs found."));
    return;
  }
  console.log("—".repeat(20));
  console.log(chalk.bold.white("here is your bug report"));
  console.log("—".repeat(20));
  const uniqueBugs = deduplicateBugs(validBugs).sort((a, b) => {
    const severityOrder: Record<Severity, number> = {
      CVE: 0,
      MAJOR: 1,
      MEDIUM: 2,
      MINOR: 3,
      UNKNOWN: 4,
    };
    const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (severityDiff !== 0) return severityDiff;
    if (a.path === b.path) {
      return a.description.localeCompare(b.description);
    }
    return a.path.localeCompare(b.path);
  });
  await saveBugs(bugFile, cacheDir, uniqueBugs);
  for (const bug of uniqueBugs) {
    const severity = (bug.severity?.toUpperCase() || "UNKNOWN") as Severity;
    const color = SEVERITY_COLORS[severity];
    console.log(color(`[${severity}] ${bug.path}`));
    console.log(chalk.white(`  ${bug.description}`));
    if (bug.cve) {
      console.log(chalk.hex("#8B0000")(`  CVE Score: ${bug.cve.score}/10`));
      console.log(
        chalk.hex("#8B0000")(`  Affected: ${bug.cve.affected.join(", ")}`),
      );
      console.log(chalk.hex("#8B0000")(`  Details: ${bug.cve.description}`));
    }
    if (bug.reasoning && Bun.env.SHOW_REASONING === "true") {
      console.log(chalk.gray(`  reasoning: ${bug.reasoning}`));
    }
    console.log("suggested change: ");
    console.log(renderDiff(bug.diff));
    console.log(
      chalk.blue(
        `  https://github.com/${owner}/${repo}/blob/${latestCommit}/${bug.path}`,
      ),
    );
    console.log("—".repeat(20));
  }
};

const run = async () => {
  const { owner, repo, branch: urlBranch } = parseRepoURL(REPO_URL);
  const { cacheDir, cacheFile, bugFile } = getCacheDir(REPO_URL);
  let branch = urlBranch;
  if (!branch) {
    branch = await fetchDefaultBranch(owner, repo);
  }
  console.log(
    chalk.blue(`repo: https://github.com/${owner}/${repo}/tree/${branch}`),
  );
  console.log(chalk.blue(`CPU core count: ${CPU_COUNT}`));
  if (IGNORE_PATTERNS.length > 0) {
    console.log(chalk.blue(`ignore patterns: ${IGNORE_PATTERNS.join(", ")}`));
  }
  if (ENABLE_CONTEXT7) {
    console.log(chalk.blue(`Context7 documentation lookup: enabled`));
  }
  console.log(chalk.magenta("Info: uses parallellism for time-saving"));
  console.log(chalk.yellow("fetching the latest commit"));
  const latestCommit = await fetchLatestCommit(owner, repo, branch);
  console.log(chalk.green(`latest commit is ${latestCommit.slice(0, 7)}`));
  const cache = await loadCache(cacheFile);
  const changedFiles: string[] = [];
  if (cache && cache.lastCommit !== latestCommit && cache.branch === branch) {
    console.log(
      chalk.yellow("changed files available in remote. pulling them.."),
    );
    const response = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/compare/${cache.lastCommit}...${latestCommit}`,
      {
        headers: getGitHubHeaders(),
      },
    );
    if (response.ok) {
      const data = await response.json();
      changedFiles.push(...data.files.map((f: any) => f.filename));
      console.log(chalk.green(`Found ${changedFiles.length} changed files`));
    }
  } else if (
    cache &&
    cache.lastCommit === latestCommit &&
    cache.branch === branch
  ) {
    const existingBugs = await loadBugs(bugFile);
    if (existingBugs.length > 0) {
      console.log(
        "nothing needs to do. you already did a codebase bug test on this repository.",
      );
      console.log(
        "if theres a new commit, you can run this command again to invalidate the cache.",
      );
      console.log(
        "if you really wanna do a bug test again, just delete cache folder and try again this command",
      );
      console.log(
        "alternatively, you can see bugs below that created in last run.",
      );
      await printBugs([], owner, repo, latestCommit, bugFile, cacheDir);
      return;
    }
  }
  const fetchSpinner = ora("fetching repository").start();
  const tree = await fetchRepoTree(owner, repo, branch);
  const newCache: CacheData = {
    lastCommit: latestCommit,
    branch,
    files: cache?.files || {},
    timestamp: Date.now(),
  };
  const itemsToFetch = tree.filter((item) => {
    if (item.size && item.size > MAX_FILE_SIZE) return false;
    const cachedFile = cache?.files[item.path];
    const isChanged = changedFiles.includes(item.path);
    if (
      cachedFile &&
      cachedFile.sha === item.sha &&
      !isChanged &&
      cache?.branch === branch
    ) {
      newCache.files[item.path] = cachedFile;
      return false;
    }
    return true;
  });
  let fetchedCount = 0;
  const fetchedFiles = await Promise.all(
    itemsToFetch.map(async (item) => {
      const content = await fetchFileContent(owner, repo, item.path, branch);
      fetchedCount++;
      fetchSpinner.text = `fetching [${fetchedCount}/${itemsToFetch.length}] files`;
      const fileEntry: FileEntry = {
        path: item.path,
        sha: item.sha,
        content,
        analyzed: false,
      };
      newCache.files[item.path] = fileEntry;
      return fileEntry;
    }),
  );
  fetchSpinner.succeed(chalk.green(`fetched ${fetchedFiles.length} files`));
  const totalFileCount = tree.length;
  const useSystemPrompt = totalFileCount < 100;
  console.log(
    chalk.blue(
      `using ${useSystemPrompt ? "system prompt" : "inline instructions"} mode (${totalFileCount} files)`,
    ),
  );
  console.log(
    chalk.blue(
      `reasoning effort: changed-files=${REASONING_EFFORT}, full-codebase=${REASONING_EFFORT_FULL}`,
    ),
  );
  const analysisSpinner = ora(
    "analyzing files and extracting dependencies",
  ).start();
  const analysisResults: FileAnalysisResult[] =
    await processInParallelWithSpinner(
      fetchedFiles,
      async (file) => {
        const bugs = await analyzeSingleFile(
          file,
          useSystemPrompt,
          REASONING_EFFORT,
        );
        const dependencies = await extractDependencies(file);
        newCache.files[file.path].analyzed = true;
        return { file, bugs, dependencies };
      },
      analysisSpinner,
      "analyzing files",
      CPU_COUNT,
    );
  const individualBugs = analysisResults.flatMap((r) => r.bugs);
  analysisSpinner.succeed(
    chalk.green(
      `finished individual analysis. found ${deduplicateBugs(individualBugs).length} bugs`,
    ),
  );
  console.log(chalk.yellow("\nbuilding the dependency graph"));
  const dependencyGraph: DependencyGraph = {};
  for (const result of analysisResults) {
    dependencyGraph[result.file.path] = result.dependencies;
  }
  console.log(
    chalk.green(
      `built dependency graph with ${Object.keys(dependencyGraph).length} files`,
    ),
  );
  console.log(chalk.yellow("\ncreating strategic batches for better quality"));
  const allFiles = Object.values(newCache.files);
  const strategicBatches = await createStrategicBatches(
    dependencyGraph,
    allFiles,
  );
  if (strategicBatches.length > 0) {
    console.log(
      chalk.green(`created ${strategicBatches.length} strategic batches`),
    );
    for (const batch of strategicBatches) {
      console.log(
        chalk.cyan(`  - ${batch.reason} (${batch.files.length} files)`),
      );
    }
  } else {
    console.log(
      chalk.yellow(
        "failed to create strategic batches, using fallback (random files, less quality)",
      ),
    );
  }
  console.log(chalk.yellow("\ndoing cross-file analyse"));
  const strategicBugs: BugData[] = [];
  const strategicSpinner = ora("").start();
  const analyzedFiles = new Set<string>();
  for (let i = 0; i < strategicBatches.length; i++) {
    const batch = strategicBatches[i];
    strategicSpinner.text = chalk.magenta(
      `[${i + 1}/${strategicBatches.length}] ${batch.reason}`,
    );
    const batchFiles = allFiles.filter((f) => batch.files.includes(f.path));
    if (batchFiles.length === 0) continue;
    const { bugs } = await analyzeFileBatch(
      batchFiles,
      [],
      useSystemPrompt,
      REASONING_EFFORT_FULL,
    );
    if (bugs.length > 0) {
      strategicBugs.push(...bugs);
    }
    batchFiles.forEach((f) => analyzedFiles.add(f.path));
  }
  strategicSpinner.succeed(
    chalk.green(
      `finished strategic analysis. found ${deduplicateBugs(strategicBugs).length} cross-file bugs`,
    ),
  );
  const remainingFiles = allFiles.filter((f) => !analyzedFiles.has(f.path));
  if (remainingFiles.length > 0) {
    console.log(
      chalk.yellow(
        `\nfallback analyze. ${remainingFiles.length} remaining files`,
      ),
    );
    const fallbackBatches = chunkArray(remainingFiles, FILES_PER_BATCH);
    const fallbackBugs: BugData[] = [];
    const fallbackSpinner = ora("").start();
    for (let i = 0; i < fallbackBatches.length; i++) {
      fallbackSpinner.text = chalk.magenta(
        `[${i + 1}/${fallbackBatches.length}] fallback batch`,
      );
      const { bugs } = await analyzeFileBatch(
        fallbackBatches[i],
        [],
        useSystemPrompt,
        REASONING_EFFORT_FULL,
      );
      if (bugs.length > 0) {
        fallbackBugs.push(...bugs);
      }
    }
    fallbackSpinner.succeed(
      chalk.green(
        `finished fallback analysis. found ${deduplicateBugs(fallbackBugs).length} bugs`,
      ),
    );
    const allBugs = deduplicateBugs([
      ...individualBugs,
      ...strategicBugs,
      ...fallbackBugs,
    ]);
    await saveCache(cacheFile, cacheDir, newCache);
    await printBugs(allBugs, owner, repo, latestCommit, bugFile, cacheDir);
  } else {
    const allBugs = deduplicateBugs([...individualBugs, ...strategicBugs]);
    await saveCache(cacheFile, cacheDir, newCache);
    await printBugs(allBugs, owner, repo, latestCommit, bugFile, cacheDir);
  }
};

run();
