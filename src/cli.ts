#!/usr/bin/env node
/**
 * RuleSight CLI — audit firestore.rules from the terminal or in CI.
 *
 *   npx rulesight firestore.rules
 *   npx rulesight firestore.rules --json
 *   npx rulesight firestore.rules --fail-on=medium
 *
 * Exit code is 1 when a finding at or above --fail-on (default: high) is found.
 */
import { readFileSync } from 'node:fs';
import { analyze, type Severity } from './core';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
const tty = process.stdout.isTTY;
const c = (code: string, s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const COLOR: Record<Severity, string> = { critical: '1;31', high: '33', medium: '36', low: '2' };

const args = process.argv.slice(2);
const files = args.filter(a => !a.startsWith('--'));
const json = args.includes('--json');
const failOn = (args.find(a => a.startsWith('--fail-on='))?.split('=')[1] ?? 'high') as Severity;

if (args.includes('--help') || files.length === 0) {
  console.log(`Usage: rulesight <firestore.rules> [--json] [--fail-on=critical|high|medium|low]`);
  process.exit(files.length === 0 && !args.includes('--help') ? 2 : 0);
}
if (!ORDER.includes(failOn)) {
  console.error(`Unknown --fail-on value: ${failOn}`);
  process.exit(2);
}

let failed = false;
const all: unknown[] = [];

for (const file of files) {
  let src: string;
  try { src = readFileSync(file, 'utf8'); }
  catch { console.error(`Cannot read ${file}`); process.exit(2); }

  const report = analyze(src);
  if (report.findings.some(f => ORDER.indexOf(f.severity) <= ORDER.indexOf(failOn))) failed = true;
  if (json) { all.push({ file, ...report }); continue; }

  console.log(`\n${c('1', file)}  ${c(report.score >= 90 ? '32' : report.score >= 55 ? '33' : '31', `${report.grade} · ${report.score}/100`)}`);
  for (const e of report.parseErrors) console.log(c('33', `  ! line ${e.line}: ${e.message}`));
  if (report.findings.length === 0) console.log(c('32', '  ✓ No issues found'));
  for (const f of report.findings) {
    console.log(`  ${c(COLOR[f.severity], f.severity.toUpperCase().padEnd(8))} ${file}:${f.line}  ${f.title} ${c('2', `[${f.id}]`)}`);
    console.log(c('2', `           ${f.detail}`));
  }
}

if (json) console.log(JSON.stringify(all.length === 1 ? all[0] : all, null, 2));
process.exit(failed ? 1 : 0);
