import { describe, expect, it } from 'vitest';
import { analyze } from './analyze';
import { parseRules, inlineFunctions, stripComments } from './parser';
import { EXAMPLES } from './examples';

const NOW = new Date('2026-11-13T00:00:00Z');
const wrap = (body: string, version = "rules_version = '2';") => `${version}
service cloud.firestore {
  match /databases/{database}/documents {
${body}
  }
}`;
const ids = (src: string) => analyze(src, NOW).findings.map(f => f.id);
const example = (id: string) => EXAMPLES.find(e => e.id === id)!.rules;

describe('parser', () => {
  it('builds full paths and strips the database prefix', () => {
    const p = parseRules(wrap(`match /users/{userId} { match /posts/{postId} { allow read: if true; } }`));
    expect(p.rules[0].path).toBe('/users/{userId}/posts/{postId}');
    expect(p.rules[0].wildcards).toEqual(['userId', 'postId']);
  });

  it('keeps correct line numbers and ignores comments', () => {
    const src = wrap(`    // allow read: if true;
    /* match /x/{y} { allow write; } */
    match /a/{b} {
      allow read: if false;
    }`);
    const p = parseRules(src);
    expect(p.rules).toHaveLength(1);
    expect(p.rules[0].line).toBe(7);
    expect(stripComments('a // b\nc')).toBe('a     \nc');
  });

  it('inlines functions with parameters', () => {
    const p = parseRules(wrap(`function isOwner(uid) { return request.auth.uid == uid; }
      match /u/{userId} { allow read: if isOwner(userId); }`));
    expect(p.rules[0].condition).toContain('request.auth.uid == userId');
    expect(inlineFunctions('f()', [])).toBe('f()');
  });

  it('reads multi-line conditions', () => {
    const p = parseRules(wrap(`match /a/{b} {
      allow create: if request.auth != null
        && request.resource.data.x is string;
    }`));
    expect(p.rules[0].condition).toBe('request.auth != null && request.resource.data.x is string');
  });
});

describe('checks', () => {
  it('RS001 — public access, no condition or if true', () => {
    expect(ids(wrap(`match /a/{b} { allow read; }`))).toContain('RS001');
    expect(ids(wrap(`match /a/{b} { allow write: if true; }`))).toContain('RS001');
    expect(ids(wrap(`match /a/{b} { allow write: if request.auth != null || true; }`))).toContain('RS001');
    const r = analyze(wrap(`match /{document=**} { allow read, write: if true; }`), NOW);
    expect(r.findings[0].title).toBe('Entire database is public');
  });

  it('RS001 — public read severity depends on what the data looks like', () => {
    const sev = (src: string) => analyze(wrap(src), NOW).findings.find(f => f.id === 'RS001')?.severity;
    expect(sev(`match /posts/{id} { allow read; }`)).toBe('low');
    expect(sev(`match /users/{id} { allow read: if true; }`)).toBe('high');
    expect(sev(`match /posts/{id} { allow read, write; }`)).toBe('critical');
  });

  it('one critical issue is enough to fail', () => {
    expect(analyze(example('test-mode'), NOW).grade).toBe('F');
  });

  it('RS002 — test mode, active vs expired', () => {
    const active = analyze(example('test-mode'), NOW).findings.find(f => f.id === 'RS002')!;
    expect(active.severity).toBe('critical');
    const expired = analyze(example('test-mode'), new Date('2027-03-01')).findings.find(f => f.id === 'RS002')!;
    expect(expired.severity).toBe('high');
    expect(expired.title).toContain('expired');
  });

  it('RS003 — auth-only recursive wildcard', () => {
    expect(ids(wrap(`match /{path=**} { allow read, write: if request.auth != null; }`))).toContain('RS003');
  });

  it('RS004 — per-user path without ownership check', () => {
    expect(ids(wrap(`match /profiles/{userId} { allow write: if request.auth != null; }`))).toContain('RS004');
    expect(ids(wrap(`match /profiles/{userId} { allow write: if request.auth.uid == userId && request.resource.data.x is string; }`))).not.toContain('RS004');
  });

  it('RS005 — signed-in is not an access rule', () => {
    const f = analyze(wrap(`match /orders/{id} { allow delete: if request.auth != null; }`), NOW).findings;
    expect(f.find(x => x.id === 'RS005')?.severity).toBe('high');
    const c = analyze(wrap(`match /msgs/{id} { allow create: if request.auth != null && request.resource.data.t is string; }`), NOW).findings;
    expect(c.find(x => x.id === 'RS005')?.severity).toBe('low');
  });

  it('RS006 — owner field not locked on update', () => {
    expect(ids(wrap(`match /p/{id} { allow update: if resource.data.ownerId == request.auth.uid; }`))).toContain('RS006');
    expect(ids(wrap(`match /p/{id} { allow update: if resource.data.ownerId == request.auth.uid && request.resource.data.ownerId == resource.data.ownerId; }`))).not.toContain('RS006');
  });

  it('RS007 — create does not enforce the owner field', () => {
    const src = wrap(`match /p/{id} {
      allow read: if resource.data.ownerId == request.auth.uid;
      allow create: if request.auth != null;
    }`);
    expect(ids(src)).toContain('RS007');
  });

  it('RS008 — self-promotion through a role field', () => {
    const r = analyze(example('startup'), NOW);
    const esc = r.findings.find(f => f.id === 'RS008');
    expect(esc?.severity).toBe('critical');
    expect(esc?.path).toBe('/users/{userId}');
  });

  it('RS009 — writes without data validation', () => {
    expect(ids(wrap(`match /p/{id} { allow update: if resource.data.o == request.auth.uid && request.resource.data.o == resource.data.o; }`))).not.toContain('RS009');
    expect(ids(wrap(`match /p/{uid} { allow write: if request.auth.uid == uid; }`))).toContain('RS009');
  });

  it('RS010 — missing rules_version', () => {
    expect(ids(wrap(`match /a/{b} { allow read: if false; }`, ''))).toContain('RS010');
  });
});

describe('report', () => {
  it('the secure reference scores an A with no serious findings', () => {
    const r = analyze(example('secure'), NOW);
    expect(r.grade).toBe('A');
    expect(r.findings.filter(f => f.severity === 'critical' || f.severity === 'high')).toEqual([]);
  });

  it('the startup example fails and finds the planted bugs', () => {
    const r = analyze(example('startup'), NOW);
    const found = new Set(r.findings.map(f => f.id));
    for (const id of ['RS001', 'RS004', 'RS006', 'RS007', 'RS008']) expect(found).toContain(id);
    expect(r.grade).toBe('F');
  });

  it('sorts by severity', () => {
    const order = ['critical', 'high', 'medium', 'low'];
    const s = analyze(example('startup'), NOW).findings.map(f => order.indexOf(f.severity));
    expect(s).toEqual([...s].sort((a, b) => a - b));
  });

  it('reports non-rules input instead of a fake score', () => {
    const r = analyze('hello world', NOW);
    expect(r.score).toBe(0);
    expect(r.parseErrors.length).toBeGreaterThan(0);
  });
});
