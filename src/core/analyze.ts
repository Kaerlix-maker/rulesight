import { expandMethods, parseRules, type AllowRule, type Method, type ParsedRules } from './parser';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  /** What is wrong and what an attacker can do with it. */
  detail: string;
  /** Concrete fix, usually a rules snippet. */
  fix: string;
  line: number;
  path: string;
}

export interface Report {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  findings: Finding[];
  stats: { matches: number; rules: number; functions: number };
  parseErrors: { message: string; line: number }[];
}

export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 40, high: 20, medium: 8, low: 3 };
const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

// ---------- condition helpers ----------

const stripParens = (c: string) => {
  let s = c.trim();
  while (s.startsWith('(') && s.endsWith(')') && balanced(s.slice(1, -1))) s = s.slice(1, -1).trim();
  return s;
};
function balanced(s: string) {
  let d = 0;
  for (const c of s) { if (c === '(') d++; if (c === ')') d--; if (d < 0) return false; }
  return d === 0;
}

/** `allow read;`, `if true`, or `... || true`. */
export function isAlwaysTrue(cond: string): boolean {
  const c = stripParens(cond);
  if (c === '' || c === 'true') return true;
  return /(^|\|\|)\s*\(*\s*true\s*\)*\s*(\|\||$)/.test(c);
}

export function isAlwaysFalse(cond: string): boolean {
  return stripParens(cond) === 'false';
}

const TEST_MODE = /request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)/;

const mentionsAuth = (c: string) => /request\.auth\b/.test(c);

/** Does the condition actually restrict *which* signed-in user gets in? */
function hasAccessControl(c: string, wildcards: string[]): boolean {
  if (/request\.auth\.(uid|token)/.test(c)) return true;
  if (/\b(get|exists|getAfter|existsAfter)\s*\(/.test(c)) return true;
  if (/(?<!request\.)resource\.data/.test(c)) return true;
  return wildcards.some(w => new RegExp(`(?<![\\w.])${w}(?![\\w])`).test(c) && /==|!=| in /.test(c));
}

/** Signed-in check only: `request.auth != null` with nothing narrowing it. */
function isAuthOnly(c: string, wildcards: string[]): boolean {
  return mentionsAuth(c) && /request\.auth\s*!=\s*null|null\s*!=\s*request\.auth/.test(c) && !hasAccessControl(c, wildcards);
}

const OWNER_WILDCARD = /^(user|uid|owner|account|member|profile|customer|client|driver|student|teacher)(_?id)?$/i;

function describeMethods(ms: Set<Method>): string {
  const reads = ms.has('get') || ms.has('list');
  const writes = ['create', 'update', 'delete'].filter(m => ms.has(m as Method));
  const parts: string[] = [];
  if (reads) parts.push('read');
  if (writes.length === 3) parts.push('create, change and delete');
  else if (writes.length) parts.push(writes.join(' and '));
  return parts.join(' and ');
}

const isRecursive = (path: string) => /=\*\*\}/.test(path);
const writesSomething = (ms: Set<Method>) => ms.has('create') || ms.has('update') || ms.has('delete');

// ---------- checks ----------

type Ctx = { parsed: ParsedRules; now: Date };
type Check = (r: AllowRule, ctx: Ctx) => Finding[];

const SENSITIVE = /(user|profile|account|order|payment|invoice|message|chat|note|private|customer|booking|ride|wallet|transaction|admin|setting|secret|token|address|phone|email)/i;

const checkPublic: Check = (r) => {
  if (!isAlwaysTrue(r.condition)) return [];
  const ms = expandMethods(r.methods);
  const what = describeMethods(ms);
  const whole = isRecursive(r.path);
  const writes = writesSomething(ms);
  const sensitive = SENSITIVE.test(r.path);
  const why = r.rawCondition ? 'The condition always evaluates to true' : 'This rule has no condition';

  if (whole || writes) {
    return [{
      id: 'RS001', severity: 'critical', line: r.line, path: r.path,
      title: whole ? 'Entire database is public' : `Anyone can ${describeMethods(new Set([...ms].filter(m => m !== 'get' && m !== 'list')))} ${r.path}`,
      detail: `${why}, so anyone on the internet — no account needed — can ${what} ${whole ? 'every document in your database' : `documents in ${r.path}`}. Your Firebase config ships inside your app's code, so finding your project takes seconds.${whole ? ' Because rules are OR-ed, this also overrides every stricter rule you wrote elsewhere.' : ''}`,
      fix: whole
        ? `// Remove the catch-all and write explicit rules per collection:\nmatch /posts/{postId} {\n  allow read: if true;            // only if posts are meant to be public\n  allow write: if request.auth != null\n               && request.resource.data.authorId == request.auth.uid;\n}`
        : `allow ${r.methods.join(', ')}: if request.auth != null\n  && resource.data.ownerId == request.auth.uid;`,
    }];
  }
  return [{
    id: 'RS001', severity: sensitive ? 'high' : 'low', line: r.line, path: r.path,
    title: sensitive ? `Public read on ${r.path} looks like private data` : `${r.path} is publicly readable`,
    detail: sensitive
      ? `${why}: anyone, without an account, can read and list every document in ${r.path}. The name suggests personal or business data — a single list query downloads all of it.`
      : `Anyone can read and list ${r.path} without signing in. That is normal for public content such as a product catalogue or blog posts — just make sure no private field (emails, phone numbers, internal notes) is stored in these documents.`,
    fix: sensitive
      ? `allow read: if request.auth != null\n  && resource.data.ownerId == request.auth.uid;`
      : `// If it must stay public, keep private fields in a separate\n// sub-collection with its own rules:\nmatch /${r.path.split('/')[1]}/{id}/private/{doc} {\n  allow read: if request.auth.uid == resource.data.ownerId;\n}`,
  }];
};

const checkTestMode: Check = (r, { now }) => {
  const m = r.condition.match(TEST_MODE);
  if (!m) return [];
  const expiry = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  const expired = expiry.getTime() < now.getTime();
  const date = expiry.toISOString().slice(0, 10);
  return [{
    id: 'RS002', severity: expired ? 'high' : 'critical', line: r.line, path: r.path,
    title: expired ? `Test-mode rules expired on ${date}` : `Test mode is on until ${date}`,
    detail: expired
      ? `These are Firebase's default "test mode" rules. They expired on ${date}, so every request to this path is now denied and your app is likely broken. Before that date, the database was open to anyone.`
      : `These are Firebase's default "test mode" rules: until ${date} anyone can read and write ${isRecursive(r.path) ? 'your whole database' : r.path} without signing in. After that date everything is denied and your app breaks. They are meant for the first day of development only.`,
    fix: `// Replace the time check with real access rules, e.g.:\nmatch /users/{userId} {\n  allow read, write: if request.auth != null && request.auth.uid == userId;\n}`,
  }];
};

const checkAuthOnly: Check = (r) => {
  if (isAlwaysTrue(r.condition) || TEST_MODE.test(r.condition)) return [];
  if (!isAuthOnly(r.condition, r.wildcards)) return [];
  const ms = expandMethods(r.methods);
  const ownerVar = r.wildcards.find(w => OWNER_WILDCARD.test(w));
  const what = describeMethods(ms);

  if (isRecursive(r.path)) {
    return [{
      id: 'RS003', severity: 'critical', line: r.line, path: r.path,
      title: 'Any signed-in user can access the entire database',
      detail: `This recursive wildcard only checks that the user is signed in. Since anyone can create an account in your app (or directly through the Firebase Auth API), any stranger can ${what} every document in every collection — including other users' private data. Rules are OR-ed, so stricter rules elsewhere do not help.`,
      fix: `// Delete the catch-all match and write one block per collection,\n// each with its own ownership check.`,
    }];
  }
  if (ownerVar) {
    return [{
      id: 'RS004', severity: 'high', line: r.line, path: r.path,
      title: `Missing ownership check on {${ownerVar}}`,
      detail: `The path is scoped per user with {${ownerVar}}, but the condition never compares it to the caller. Any signed-in user can ${what} any other user's document just by changing the ID in the request.`,
      fix: `allow ${r.methods.join(', ')}: if request.auth != null && request.auth.uid == ${ownerVar};`,
    }];
  }
  const destructive = ms.has('update') || ms.has('delete');
  const onlyCreate = ms.size === 1 && ms.has('create');
  return [{
    id: 'RS005', severity: destructive ? 'high' : onlyCreate ? 'low' : 'medium', line: r.line, path: r.path,
    title: destructive ? `Any signed-in user can modify or delete ${r.path}` : onlyCreate ? `Any signed-in user can create in ${r.path}` : `Any signed-in user can read all of ${r.path}`,
    detail: destructive
      ? `"Signed in" is not an access rule: anyone can create an account. Any user can ${what} documents that belong to other people — for example wipe the whole collection with a short script.`
      : onlyCreate
        ? `Creating is allowed for every signed-in user. That can be intended (posts, messages), but make sure the new document is tied to its author and its fields are validated.`
        : `Every signed-in user can read every document here, including with list queries that download the whole collection. Fine for public content, a data leak for anything personal.`,
    fix: destructive
      ? `allow update, delete: if request.auth != null\n  && resource.data.ownerId == request.auth.uid;`
      : onlyCreate
        ? `allow create: if request.auth != null\n  && request.resource.data.ownerId == request.auth.uid;`
        : `allow read: if request.auth != null\n  && resource.data.ownerId == request.auth.uid;`,
  }];
};

/** Owner field checked on the old doc but not on the new one → ownership can be handed to someone else (or forged on create). */
const checkOwnerField: Check = (r, { parsed }) => {
  const ms = expandMethods(r.methods);
  const out: Finding[] = [];
  const re = /(?<!request\.)resource\.data\.(\w+)\s*==\s*request\.auth\.uid|request\.auth\.uid\s*==\s*(?<!request\.)resource\.data\.(\w+)/g;
  const fields = new Set([...r.condition.matchAll(re)].map(m => m[1] ?? m[2]));
  if (ms.has('update')) {
    for (const f of fields) {
      if (!new RegExp(`request\\.resource\\.data\\.${f}\\b|affectedKeys|hasOnly|diff\\(`).test(r.condition)) {
        out.push({
          id: 'RS006', severity: 'medium', line: r.line, path: r.path,
          title: `Owner can rewrite the "${f}" field`,
          detail: `Updates are allowed when the current document's ${f} matches the caller, but the new value of ${f} is never checked. The owner can set ${f} to another user's ID and plant a document in their account — or, if ${f} grants permissions elsewhere, move data around freely.`,
          fix: `allow update: if request.auth != null\n  && resource.data.${f} == request.auth.uid\n  && request.resource.data.${f} == resource.data.${f};`,
        });
      }
    }
  }
  // create: siblings use an owner field, but create does not enforce it
  if (ms.has('create')) {
    const siblings = parsed.rules.filter(x => x.path === r.path && x !== r);
    const ownerFields = new Set(siblings.flatMap(x => [...x.condition.matchAll(re)].map(m => m[1] ?? m[2])));
    for (const f of ownerFields) {
      if (!new RegExp(`request\\.resource\\.data\\.${f}\\s*==\\s*request\\.auth\\.uid|request\\.auth\\.uid\\s*==\\s*request\\.resource\\.data\\.${f}`).test(r.condition)
        && !isAlwaysFalse(r.condition)) {
        out.push({
          id: 'RS007', severity: 'high', line: r.line, path: r.path,
          title: `Documents can be created in someone else's name`,
          detail: `Other rules on ${r.path} treat "${f}" as the owner, but create never checks it. A user can create a document with ${f} set to a victim's ID — fake posts, fake orders or fake bookings that appear in the victim's account.`,
          fix: `allow create: if request.auth != null\n  && request.resource.data.${f} == request.auth.uid;`,
        });
      }
    }
  }
  return out;
};

/** Role read from a user-writable document → users can make themselves admin. */
function checkPrivilegeEscalation(parsed: ParsedRules): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  const roleRe = /get\(\s*\/databases\/\$\(database\)\/documents\/(\w+)\/(?:\$\([^)]*\)|[^)/\s]+)\s*\)\.data\.(\w+)/g;
  const refs = parsed.rules.flatMap(r => [...r.condition.matchAll(roleRe)].map(m => ({ col: m[1], field: m[2] })));
  for (const { col, field } of refs) {
    const key = `${col}.${field}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const holders = parsed.rules.filter(r => new RegExp(`^/${col}/\\{\\w+\\}$`).test(r.path));
    for (const r of holders) {
      const ms = expandMethods(r.methods);
      if (!(ms.has('create') || ms.has('update'))) continue;
      if (isAlwaysFalse(r.condition)) continue;
      const selfWrite = isAlwaysTrue(r.condition) || /request\.auth\.uid/.test(r.condition) || isAuthOnly(r.condition, r.wildcards);
      const guarded = new RegExp(`request\\.resource\\.data\\.${field}\\b|affectedKeys|hasOnly|hasAny|diff\\(|['"]${field}['"]`).test(r.condition);
      if (selfWrite && !guarded) {
        out.push({
          id: 'RS008', severity: 'critical', line: r.line, path: r.path,
          title: `Users can promote themselves via "${field}"`,
          detail: `Your rules trust ${col}/{id}.${field} to grant privileges, but users are allowed to write their own ${col} document without any restriction on "${field}". Anyone can sign up, set ${field} to an admin value from the browser console, and get admin access everywhere this check is used.`,
          fix: `// Block the privileged field on user writes:\nallow update: if request.auth.uid == ${r.wildcards[0] ?? 'userId'}\n  && !request.resource.data.diff(resource.data)\n        .affectedKeys().hasAny(['${field}']);\nallow create: if request.auth.uid == ${r.wildcards[0] ?? 'userId'}\n  && !('${field}' in request.resource.data);\n// Better: store roles in Auth custom claims (request.auth.token.${field}).`,
        });
      }
    }
  }
  return out;
}

/** Writes allowed with no validation of the incoming data. */
const checkValidation: Check = (r) => {
  const ms = expandMethods(r.methods);
  if (!(ms.has('create') || ms.has('update'))) return [];
  if (isAlwaysTrue(r.condition) || isAlwaysFalse(r.condition) || TEST_MODE.test(r.condition)) return [];
  if (/request\.resource\.data/.test(r.condition)) return [];
  return [{
    id: 'RS009', severity: 'low', line: r.line, path: r.path,
    title: `No data validation on writes to ${r.path}`,
    detail: `The rule checks who may write, but not what they write. A user can add any field, use wrong types, or store megabytes of junk (which you pay for in storage and reads).`,
    fix: `allow create, update: if /* existing checks */\n  && request.resource.data.keys().hasOnly(['title', 'body', 'ownerId'])\n  && request.resource.data.title is string\n  && request.resource.data.title.size() < 200;`,
  }];
};

const RULE_CHECKS: Check[] = [checkPublic, checkTestMode, checkAuthOnly, checkOwnerField, checkValidation];

// ---------- entry point ----------

export function analyze(source: string, now: Date = new Date()): Report {
  const parsed = parseRules(source);
  const ctx: Ctx = { parsed, now };
  const findings: Finding[] = [];

  if (!parsed.service) {
    parsed.errors.push({ message: 'No `service cloud.firestore { ... }` block found — is this a Firestore rules file?', line: 1 });
  }
  if (parsed.service && parsed.rulesVersion !== '2') {
    findings.push({
      id: 'RS010', severity: 'low', line: 1, path: '/',
      title: parsed.rulesVersion ? `Old rules_version '${parsed.rulesVersion}'` : 'rules_version is not set',
      detail: `Without rules_version = '2', recursive wildcards ({name=**}) behave differently and collection-group queries cannot be secured. Version 2 is the current default.`,
      fix: `rules_version = '2';`,
    });
  }

  for (const r of parsed.rules) for (const c of RULE_CHECKS) findings.push(...c(r, ctx));
  findings.push(...checkPrivilegeEscalation(parsed));

  // De-duplicate: a public rule does not also need a "no validation" note, etc.
  const critLines = new Set(findings.filter(f => f.severity === 'critical').map(f => f.line));
  const forgedLines = new Set(findings.filter(f => f.id === 'RS007').map(f => f.line));
  const filtered = findings.filter(f =>
    !(f.id === 'RS009' && critLines.has(f.line)) &&
    !(f.id === 'RS005' && f.severity === 'low' && forgedLines.has(f.line)));
  // Collapse repeated RS009 per path.
  const seen = new Set<string>();
  const unique = filtered.filter(f => { const k = `${f.id}|${f.path}|${f.title}`; if (seen.has(k)) return false; seen.add(k); return true; });

  unique.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || a.line - b.line);

  const penalty = unique.reduce((s, f) => s + SEVERITY_WEIGHT[f.severity], 0);
  // A single critical issue is enough to fail: cap the score, then subtract.
  const cap = unique.some(f => f.severity === 'critical') ? 30 : unique.some(f => f.severity === 'high') ? 70 : 100;
  const score = parsed.rules.length === 0 && parsed.errors.length ? 0 : Math.max(0, Math.min(cap, 100 - penalty));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';

  return {
    score, grade, findings: unique,
    stats: { matches: parsed.matches.length, rules: parsed.rules.length, functions: parsed.functions.length },
    parseErrors: parsed.errors,
  };
}
