import { useDeferredValue, useMemo, useRef, useState } from 'react';
import { analyze, type Finding, type Severity } from './core';
import { EXAMPLES } from './core/examples';
import './App.css';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const REPO = 'https://github.com/kaerlix-maker/rulesight';

export default function App() {
  const [source, setSource] = useState(EXAMPLES[1].rules);
  const [active, setActive] = useState<string | null>(EXAMPLES[1].id);
  const [focusLine, setFocusLine] = useState<number | null>(null);
  const [open, setOpen] = useState<number | null>(0);
  const deferred = useDeferredValue(source);
  const report = useMemo(() => analyze(deferred), [deferred]);
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const hiRef = useRef<HTMLDivElement>(null);

  const lines = source.split('\n').length;
  const counts = SEVERITIES.map(s => [s, report.findings.filter(f => f.severity === s).length] as const);
  const empty = source.trim() === '';

  const syncScroll = () => {
    const t = editorRef.current;
    if (!t) return;
    if (gutterRef.current) gutterRef.current.scrollTop = t.scrollTop;
    if (hiRef.current) hiRef.current.style.transform = `translateY(${-t.scrollTop}px)`;
  };

  const jumpTo = (line: number) => {
    setFocusLine(line);
    const t = editorRef.current;
    if (!t) return;
    const lh = parseFloat(getComputedStyle(t).lineHeight);
    t.scrollTop = Math.max(0, (line - 4) * lh);
    syncScroll();
    if (window.matchMedia('(max-width: 960px)').matches) t.scrollIntoView({ behavior: 'smooth', block: 'center' });
  };

  return (
    <div className="app">
      <header className="top">
        <a className="brand" href="#">
          <Logo /> RuleSight
        </a>
        <nav>
          <span className="pill"><i /> Runs 100% in your browser</span>
          <a href={REPO} target="_blank" rel="noopener">GitHub ↗</a>
        </nav>
      </header>

      <section className="intro">
        <p className="eyebrow">Firestore security rules auditor</p>
        <h1>Find the holes in your rules <em>before someone else does.</em></h1>
        <p className="lede">Paste your <code>firestore.rules</code>. RuleSight explains every risk in plain language and gives you the fix. Nothing is uploaded — your rules never leave this page.</p>
      </section>

      <main className="grid">
        <section className="panel editor-panel">
          <div className="panel-head">
            <div className="tabs" role="tablist">
              {EXAMPLES.map(e => (
                <button key={e.id} role="tab" aria-selected={active === e.id} className={active === e.id ? 'on' : ''}
                  onClick={() => { setSource(e.rules); setActive(e.id); setFocusLine(null); setOpen(0); }}>
                  {e.label}
                </button>
              ))}
            </div>
            <button className="ghost" onClick={() => { setSource(''); setActive(null); editorRef.current?.focus(); }}>Clear</button>
          </div>
          <div className="editor">
            <div className="gutter" ref={gutterRef} aria-hidden>
              {Array.from({ length: lines }, (_, i) => (
                <div key={i} className={focusLine === i + 1 ? 'hl' : report.findings.some(f => f.line === i + 1) ? 'mark' : ''}>{i + 1}</div>
              ))}
            </div>
            <div className="code-wrap">
              <div className="hi-layer" ref={hiRef} aria-hidden>
                {focusLine && <div className="hi-line" style={{ top: `calc(${focusLine - 1} * var(--lh) + var(--pad-y))` }} />}
              </div>
              <textarea
                ref={editorRef}
                value={source}
                spellCheck={false}
                aria-label="Firestore rules"
                placeholder="Paste your firestore.rules here…"
                onScroll={syncScroll}
                onChange={e => { setSource(e.target.value); setActive(null); setFocusLine(null); }}
              />
            </div>
          </div>
          <div className="panel-foot">
            <span>{report.stats.matches} match blocks · {report.stats.rules} rules · {report.stats.functions} functions</span>
            <span>Firestore · rules_version 2</span>
          </div>
        </section>

        <section className="panel report">
          {empty ? (
            <div className="empty">
              <Logo big />
              <p>Paste your rules on the left, or pick an example.</p>
            </div>
          ) : (
            <>
              <div className="summary">
                <ScoreRing score={report.score} grade={report.grade} />
                <div className="summary-text">
                  <h2>{verdict(report.score, report.findings)}</h2>
                  <div className="counts">
                    {counts.map(([s, n]) => (
                      <span key={s} className={`count ${s} ${n ? '' : 'zero'}`}><b>{n}</b>{s}</span>
                    ))}
                  </div>
                </div>
              </div>

              {report.parseErrors.length > 0 && (
                <div className="parse-errors">
                  {report.parseErrors.map((e, i) => <p key={i}>Line {e.line}: {e.message}</p>)}
                </div>
              )}

              <ol className="findings">
                {report.findings.length === 0 && !report.parseErrors.length && (
                  <li className="clean">No issues found. Remember: rules are only half of security — review your Cloud Functions and Auth settings too.</li>
                )}
                {report.findings.map((f, i) => (
                  <FindingCard key={`${f.id}-${f.line}-${i}`} f={f} open={open === i}
                    onToggle={() => { setOpen(open === i ? null : i); jumpTo(f.line); }} />
                ))}
              </ol>
            </>
          )}
        </section>
      </main>

      <footer className="foot">
        <span>RuleSight is open source (MIT). A static analyzer finds common mistakes — it does not replace a full security review.</span>
        <span>Built by <a href="https://github.com/kaerlix-maker" target="_blank" rel="noopener">Kaerlix</a></span>
      </footer>
    </div>
  );
}

function verdict(score: number, findings: Finding[]) {
  if (findings.some(f => f.severity === 'critical')) return 'Critical issues — your data is exposed.';
  if (findings.some(f => f.severity === 'high')) return 'Serious gaps that attackers can use.';
  if (score >= 90) return 'Solid rules. Only minor notes.';
  return 'Mostly fine, with room to harden.';
}

function FindingCard({ f, open, onToggle }: { f: Finding; open: boolean; onToggle: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(f.fix); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard blocked */ }
  };
  return (
    <li className={`finding ${f.severity} ${open ? 'open' : ''}`}>
      <button className="finding-head" onClick={onToggle} aria-expanded={open}>
        <span className={`sev ${f.severity}`}>{f.severity}</span>
        <span className="f-title">{f.title}</span>
        <span className="f-line">L{f.line}</span>
      </button>
      {open && (
        <div className="finding-body">
          <p className="f-path"><code>{f.path}</code> · {f.id}</p>
          <p>{f.detail}</p>
          <div className="fix">
            <div className="fix-head"><span>Suggested fix</span><button className="ghost sm" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button></div>
            <pre><code>{f.fix}</code></pre>
          </div>
        </div>
      )}
    </li>
  );
}

function ScoreRing({ score, grade }: { score: number; grade: string }) {
  const r = 52, c = 2 * Math.PI * r;
  const tone = score >= 90 ? 'var(--ok)' : score >= 55 ? 'var(--gold)' : 'var(--crit)';
  return (
    <div className="ring" style={{ ['--tone' as string]: tone }}>
      <svg viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} className="track" />
        <circle cx="60" cy="60" r={r} className="bar" strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} />
      </svg>
      <div className="ring-text"><b>{grade}</b><span>{score}/100</span></div>
    </div>
  );
}

function Logo({ big }: { big?: boolean }) {
  const s = big ? 48 : 22;
  return (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M12 2.5 4 5.5v6c0 4.8 3.3 8.6 8 10 4.7-1.4 8-5.2 8-10v-6l-8-3Z" stroke="var(--gold)" strokeWidth="1.5" strokeLinejoin="round" />
      <circle cx="11.5" cy="11" r="3.2" stroke="var(--text)" strokeWidth="1.5" />
      <path d="m14 13.5 2.6 2.6" stroke="var(--text)" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}
