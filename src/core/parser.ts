/**
 * A small, dependency-free parser for Firestore security rules.
 *
 * It does not try to be a full grammar. It understands the structure that
 * matters for a security review: `match` blocks (nested), `allow` statements
 * with their conditions, and `function` declarations (so calls can be inlined
 * before the checks run). Line numbers are preserved for every rule.
 */

export type Method = 'read' | 'write' | 'get' | 'list' | 'create' | 'update' | 'delete';

export interface FunctionDef {
  name: string;
  params: string[];
  body: string; // the expression after `return`
}

export interface AllowRule {
  methods: Method[];
  /** Condition exactly as written (whitespace-normalised). Empty = no `if`. */
  rawCondition: string;
  /** Condition with user functions inlined — this is what the checks read. */
  condition: string;
  line: number;
  /** Full path of the enclosing match, e.g. `/users/{userId}`. */
  path: string;
  /** Wildcard variable names in scope, e.g. ['userId']. */
  wildcards: string[];
}

export interface MatchBlock {
  path: string;
  line: number;
  rules: AllowRule[];
}

export interface ParsedRules {
  rulesVersion: string | null;
  service: string | null;
  matches: MatchBlock[];
  rules: AllowRule[];
  functions: FunctionDef[];
  errors: { message: string; line: number }[];
}

const DB_PREFIX = /^\/databases\/\{[^}]+\}\/documents/;

/** Replace comments with spaces so offsets and line numbers stay valid. */
export function stripComments(src: string): string {
  let out = '';
  let i = 0;
  let quote: string | null = null;
  while (i < src.length) {
    const c = src[i];
    const n = src[i + 1];
    if (quote) {
      out += c;
      if (c === '\\') { out += n ?? ''; i += 2; continue; }
      if (c === quote) quote = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; out += c; i++; continue; }
    if (c === '/' && n === '/') {
      while (i < src.length && src[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (c === '/' && n === '*') {
      out += '  '; i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += '  '; i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

const norm = (s: string) => s.replace(/\s+/g, ' ').trim();

/** Split `a, f(b, c), d` on top-level commas. */
export function splitTopLevel(s: string, sep = ','): string[] {
  const parts: string[] = [];
  let depth = 0, cur = '', quote: string | null = null;
  for (const c of s) {
    if (quote) { cur += c; if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'") { quote = c; cur += c; continue; }
    if ('([{'.includes(c)) depth++;
    if (')]}'.includes(c)) depth--;
    if (c === sep && depth === 0) { parts.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

/** Inline calls to user-defined functions, up to a fixed depth. */
export function inlineFunctions(cond: string, fns: FunctionDef[], depth = 6): string {
  if (!cond || depth === 0 || fns.length === 0) return cond;
  let changed = false;
  let out = cond;
  for (const fn of fns) {
    const re = new RegExp(`(?<![\\w.])${fn.name}\\s*\\(`, 'g');
    let m: RegExpExecArray | null;
    let result = '';
    let last = 0;
    while ((m = re.exec(out))) {
      // find matching paren
      let i = m.index + m[0].length, d = 1;
      while (i < out.length && d > 0) {
        if (out[i] === '(') d++;
        else if (out[i] === ')') d--;
        i++;
      }
      const args = splitTopLevel(out.slice(m.index + m[0].length, i - 1));
      let body = fn.body;
      fn.params.forEach((p, k) => {
        body = body.replace(new RegExp(`(?<![\\w.])${p}(?![\\w])`, 'g'), args[k] ?? p);
      });
      result += out.slice(last, m.index) + `(${body})`;
      last = i;
      re.lastIndex = i;
      changed = true;
    }
    out = result + out.slice(last);
  }
  return changed ? inlineFunctions(out, fns, depth - 1) : out;
}

const METHODS: Method[] = ['read', 'write', 'get', 'list', 'create', 'update', 'delete'];

export function parseRules(source: string): ParsedRules {
  const src = stripComments(source);
  const lineAt = (idx: number) => src.slice(0, idx).split('\n').length;
  const result: ParsedRules = { rulesVersion: null, service: null, matches: [], rules: [], functions: [], errors: [] };

  const rv = src.match(/rules_version\s*=\s*['"]([^'"]+)['"]/);
  if (rv) result.rulesVersion = rv[1];
  const sv = src.match(/service\s+([\w.]+)\s*\{/);
  if (sv) result.service = sv[1];

  // Pass 1: collect functions (global scope is fine for a review tool).
  const fnRe = /function\s+(\w+)\s*\(([^)]*)\)\s*\{/g;
  let fm: RegExpExecArray | null;
  while ((fm = fnRe.exec(src))) {
    let i = fm.index + fm[0].length, d = 1;
    const start = i;
    while (i < src.length && d > 0) {
      if (src[i] === '{') d++; else if (src[i] === '}') d--;
      i++;
    }
    const block = src.slice(start, i - 1);
    // Support `let x = ...;` bindings by substituting them into the return.
    const lets = [...block.matchAll(/let\s+(\w+)\s*=\s*([^;]+);/g)];
    const ret = block.match(/return\s+([\s\S]*?);?\s*$/);
    if (!ret) { result.errors.push({ message: `Function ${fm[1]} has no return`, line: lineAt(fm.index) }); continue; }
    let body = norm(ret[1].replace(/;\s*$/, ''));
    for (const [, name, val] of lets.reverse()) {
      body = body.replace(new RegExp(`(?<![\\w.])${name}(?![\\w])`, 'g'), `(${norm(val)})`);
    }
    result.functions.push({ name: fm[1], params: fm[2].split(',').map(s => s.trim()).filter(Boolean), body });
  }

  // Pass 2: walk blocks with a stack of match paths.
  const stack: { kind: 'match' | 'other'; path: string; block?: MatchBlock }[] = [];
  const currentPath = () => stack.filter(s => s.kind === 'match').map(s => s.path).join('');
  let i = 0;
  while (i < src.length) {
    const rest = src.slice(i);
    let m: RegExpMatchArray | null;

    if ((m = rest.match(/^match\s+(\/\S*?)\s*\{(?!\w)/))) {
      const full = (currentPath() + m[1]).replace(DB_PREFIX, '') || '/';
      const block: MatchBlock = { path: full, line: lineAt(i), rules: [] };
      result.matches.push(block);
      stack.push({ kind: 'match', path: m[1], block });
      i += m[0].length;
      continue;
    }
    if ((m = rest.match(/^function\s+\w+\s*\([^)]*\)\s*\{/))) {
      // skip the whole function body
      let j = i + m[0].length, d = 1;
      while (j < src.length && d > 0) { if (src[j] === '{') d++; else if (src[j] === '}') d--; j++; }
      i = j;
      continue;
    }
    if ((m = rest.match(/^allow\s+([\w\s,]+?)\s*(:|;)/))) {
      const methods = m[1].split(',').map(s => s.trim()).filter(Boolean) as Method[];
      const bad = methods.filter(x => !METHODS.includes(x));
      const line = lineAt(i);
      let j = i + m[0].length;
      let raw = '';
      if (m[2] === ':') {
        // read until `;` at depth 0
        let d = 0, quote: string | null = null;
        const start = j;
        while (j < src.length) {
          const c = src[j];
          if (quote) { if (c === quote) quote = null; }
          else if (c === '"' || c === "'") quote = c;
          else if ('([{'.includes(c)) d++;
          else if (')]}'.includes(c)) { if (d === 0) break; d--; }
          else if (c === ';' && d === 0) break;
          j++;
        }
        raw = norm(src.slice(start, j)).replace(/^if\s+/, '');
        if (src[j] === ';') j++;
      }
      if (bad.length) result.errors.push({ message: `Unknown method: ${bad.join(', ')}`, line });
      const path = currentPath().replace(DB_PREFIX, '') || '/';
      const wildcards = [...path.matchAll(/\{(\w+)(?:=\*\*)?\}/g)].map(x => x[1]);
      const rule: AllowRule = {
        methods: methods.filter(x => METHODS.includes(x)),
        rawCondition: raw,
        condition: norm(inlineFunctions(raw, result.functions)),
        line, path, wildcards,
      };
      result.rules.push(rule);
      const top = [...stack].reverse().find(s => s.kind === 'match');
      top?.block?.rules.push(rule);
      i = j;
      continue;
    }
    if (src[i] === '{') { stack.push({ kind: 'other', path: '' }); i++; continue; }
    if (src[i] === '}') { stack.pop(); i++; continue; }
    // skip identifiers/strings quickly
    if (src[i] === '"' || src[i] === "'") {
      const q = src[i]; i++;
      while (i < src.length && src[i] !== q) i++;
      i++;
      continue;
    }
    i++;
  }
  return result;
}

/** Expand `read`/`write` into the granular methods they cover. */
export function expandMethods(methods: Method[]): Set<Method> {
  const s = new Set<Method>();
  for (const m of methods) {
    if (m === 'read') { s.add('get'); s.add('list'); }
    else if (m === 'write') { s.add('create'); s.add('update'); s.add('delete'); }
    else s.add(m);
  }
  return s;
}
