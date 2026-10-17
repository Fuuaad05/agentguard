import { useState } from 'react';
import { ArrowUpRight, ArrowRight, Check, ChevronDown, ChevronUp, CircleAlert, Clipboard, Code2, FileCode2, Fingerprint, GitCompareArrows, LoaderCircle, ScanLine, ShieldCheck, X } from 'lucide-react';
import './App.css';

const vulnerable = `import sqlite3

def calculate(expression):
    return eval(expression)

def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()

def authenticate(password):
    return password == "admin123"`;
const safe = `import sqlite3

def calculate(a, b):
    return a + b

def get_user(username):
    conn = sqlite3.connect("users.db")
    return conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()`;
const severityClass = (s) => (s || 'unrated').toLowerCase().replace(/[^a-z]/g, '');
const statusText = {
  static_pattern_confirmed: 'Supported by AST pattern evidence',
  static_only: 'AST-only detection · review required',
  ai_only: 'AI-only assessment · review required',
};
function CodeLines({ code }) {
  return <div className="code-lines" aria-hidden="true">{code.split('\n').map((_, i) => <span key={i}>{i + 1}</span>)}</div>;
}
function Finding({ item, index, onGeneratePatch, patchLoading }) {
  const [open, setOpen] = useState(index === 0);
  return <article className={`finding finding-${severityClass(item.severity)}`}>
    <button type="button" className="finding-head" onClick={() => setOpen(!open)} aria-expanded={open}>
      <span className="finding-index">{String(index + 1).padStart(2, '0')}</span>
      <span className="finding-heading"><strong>{item.title}</strong><small>{item.category || 'Unclassified'} <span className="mid-dot">·</span> Line {item.line ?? '—'}</small></span>
      <span className={`severity-tag severity-${severityClass(item.severity)}`}>{item.severity || 'Unrated'}</span>
      {open ? <ChevronUp size={17}/> : <ChevronDown size={17}/>}
    </button>
    {open && <div className="finding-body">
      <p className="finding-explanation">{item.explanation}</p>
      <div className="finding-detail-grid">
        <div><span className="eyebrow">RECOMMENDED FIX</span><p>{item.recommendation}</p></div>
        <div><span className="eyebrow">HOW TO CHECK</span><p>{item.verification}</p></div>
      </div>
      <div className="finding-foot"><span className="evidence-dot"/> {statusText[item.verificationStatus] || 'Potential finding · not exploit-verified'} <span className="confidence">Confidence: {item.confidence || '—'}</span></div>
      {/^CWE-\d{1,5}$/.test(item.category || '') && Number.isInteger(item.line) && item.line > 0 && (
        <div className="finding-patch-action">
          <button type="button" className="generate-patch-button" disabled={patchLoading} onClick={() => onGeneratePatch(item)}>
            {patchLoading ? <LoaderCircle size={16} className="spin"/> : <GitCompareArrows size={16}/>}
            {patchLoading ? 'Generating fix…' : 'Generate suggested fix'}
            <ArrowUpRight size={15}/>
          </button>
        </div>
      )}
    </div>}
  </article>;
}
export default function App() {
  const [code, setCode] = useState(vulnerable);
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('findings');
  const [copied, setCopied] = useState(false);
  const [patch, setPatch] = useState(null);
  const [patchLoading, setPatchLoading] = useState(false);
  const [patchError, setPatchError] = useState('');
  const [patchFinding, setPatchFinding] = useState(null);
  const [patchSource, setPatchSource] = useState('');
  const [scanSource, setScanSource] = useState('');
  const [patchTestApproval, setPatchTestApproval] = useState(false);
  const [patchTestResult, setPatchTestResult] = useState(null);
  const [patchTestError, setPatchTestError] = useState('');
  const [patchTestBusy, setPatchTestBusy] = useState(false);
  function clearPatch() {
    setPatch(null);
    setPatchError('');
    setPatchFinding(null);
    setPatchSource('');
    setPatchTestApproval(false); setPatchTestResult(null); setPatchTestError('');
  }
  function updateCode(nextCode) {
    setCode(nextCode);
    setFinding(null);
    setScanSource('');
    setError('');
    clearPatch();
  }
  async function generatePatch(item) {
    if (patchLoading || loading || !finding || !scanSource) return;
    const source = scanSource;
    setPatchLoading(true);
    setPatch(null);
    setPatchTestApproval(false); setPatchTestResult(null); setPatchTestError('');
    setPatchError('');
    setPatchFinding(item);
    setPatchSource(source);
    try {
      const response = await fetch('http://localhost:3001/api/patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: source, category: item.category, line: item.line })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Patch generation failed.');
      if (typeof data.patchedCode !== 'string' || !data.patchedCode.trim()) throw new Error('Invalid patch response.');
      setPatch(data);
      setTimeout(() => document.getElementById('patch-review')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80);
    } catch (err) {
      setPatchError(err.message || 'Could not generate a patch.');
    } finally {
      setPatchLoading(false);
    }
  }
  async function loadReviewedRepair() {
    if (patchLoading || loading || !scanSource) return;
    setPatchLoading(true); setPatch(null); setPatchError('');
    setPatchTestApproval(false); setPatchTestResult(null); setPatchTestError('');
    setPatchSource(scanSource);
    setPatchFinding({ category: 'CWE-94', line: 4 });
    try {
      const response = await fetch('http://localhost:3001/api/reviewed-repair', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: scanSource, category: 'CWE-94' })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Reviewed repair unavailable.');
      setPatch(data);
      setTimeout(() => document.getElementById('patch-review')?.scrollIntoView({ behavior: 'smooth' }), 80);
    } catch (error) { setPatchError(error.message); }
    finally { setPatchLoading(false); }
  }
  async function testDisplayedRepair() {
    if (!patch?.patchId || !patchTestApproval || patchTestBusy) return;
    setPatchTestBusy(true); setPatchTestResult(null); setPatchTestError('');
    try {
      const response = await fetch('http://localhost:3001/api/test-reviewed-patch', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ patchId: patch.patchId, approved: true })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'CreateOS test failed.');
      setPatchTestResult(data);
    } catch (error) { setPatchTestError(error.message); }
    finally { setPatchTestBusy(false); }
  }
  async function analyze() {
    if (patchLoading) return;
    setLoading(true); setFinding(null); setScanSource(''); setError(''); setTab('findings'); clearPatch();
    try {
      const response = await fetch('http://localhost:3001/api/analyze', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({code}) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'The scan could not be completed.');
      if (!Array.isArray(data.findings)) throw new Error('Unexpected scanner response. Check the backend version.');
      setScanSource(code);
      setFinding(data);
    } catch (e) { setError(e.message || 'Unable to connect to the scanner.'); }
    finally { setLoading(false); }
  }
  function loadExample(example) { if (!patchLoading && !loading) updateCode(example); }
  async function copyReport() {
    if (!finding) return;
    const text = [`AgentGuard security review`, finding.summary, '', ...finding.findings.map((f,i)=>`${i+1}. ${f.title} [${f.severity}] ${f.category} line ${f.line}\n${f.explanation}\nFix: ${f.recommendation}\nStatus: ${statusText[f.verificationStatus] || 'Potential'}`)].join('\n');
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(()=>setCopied(false),1800); } catch { setError('Could not copy report.'); }
  }

  const total = finding?.findings?.length ?? 0;
  const staticCount = finding?.verification?.evidence?.length ?? 0;
  return <div className="site-shell">
    <div className="top-rule"/>
    <header className="site-header">
      <a className="brand" href="#top" aria-label="AgentGuard home"><span className="brand-symbol"><ShieldCheck size={20} strokeWidth={2.3}/></span><span>agentguard<span className="brand-period">.</span></span></a>
      <nav className="top-nav" aria-label="Primary"><a href="#workspace" className="nav-selected">Workbench</a><a href="#how-it-works">Method</a><a href="#results">Results</a></nav>
      <span className="header-label"><span className="live-dot"/> LOCAL BUILD <span className="header-version">/ v0.3</span></span>
    </header>
    <main id="top">
      <section className="intro" aria-labelledby="intro-heading">
        <div className="intro-top"><span className="eyebrow"><span className="eyebrow-mark">/</span> CODE SECURITY WORKBENCH</span><span className="edition">01 — PYTHON ANALYSIS</span></div>
        <div className="intro-content"><div><h1 id="intro-heading">Find the flaw.<br/><em>Understand the fix.</em></h1><p>Paste Python code. Get a clear account of what looks risky, where it lives, and what to change. No theatrics. Just useful security review.</p><a className="intro-link" href="#workspace">Go to the workbench <ArrowRight size={17}/></a></div><div className="intro-side"><span className="intro-side-num">AG—01</span><p>AI-assisted review<br/>Independent AST checks<br/>Evidence, not assumptions.</p></div></div>
      </section>
      <section className="workbench" id="workspace" aria-label="Security workbench">
        <div className="section-heading"><div><span className="eyebrow">01 / THE WORKBENCH</span><h2>Inspect your code.</h2></div><span className="section-side">Python <span className="mid-dot">/</span> Gemini + AST</span></div>
        <div className="editor-shell">
          <div className="editor-toolbar"><div className="file-name"><FileCode2 size={16}/> review.py <span className="file-tag">PYTHON</span></div><div className="editor-actions"><button type="button" onClick={()=>loadExample(vulnerable)}>Vulnerable example</button><span className="toolbar-divider"/><button type="button" onClick={()=>loadExample(safe)}>Safer example</button><button type="button" className="icon-button" onClick={()=>loadExample('')} title="Clear editor" aria-label="Clear editor"><X size={16}/></button></div></div>
          <div className="editor-body"><CodeLines code={code}/><textarea aria-label="Python source code" spellCheck="false" value={code} disabled={loading || patchLoading} onChange={e=>updateCode(e.target.value)} placeholder="# Paste Python code to inspect..." /></div>
          <div className="editor-footer"><span><span className="footer-square"/> {code.split('\n').length} lines <span className="mid-dot">·</span> Code is sent to your configured analysis API</span><button className="scan-button" type="button" disabled={loading || patchLoading || !code.trim()} onClick={analyze}>{loading ? <LoaderCircle size={17} className="spin"/> : <ScanLine size={17}/>} {loading ? 'Reviewing code…' : 'Run security scan'} <ArrowUpRight size={16}/></button></div>
        </div>
        {error && <div className="error-banner" role="alert"><CircleAlert size={18}/><span>{error}</span><button type="button" onClick={()=>setError('')} aria-label="Dismiss error"><X size={17}/></button></div>}
      </section>
      <section className="results-section" id="results" aria-label="Scan results"><div className="section-heading"><div><span className="eyebrow">02 / REVIEW OUTPUT</span><h2>The findings.</h2></div>{finding && <button className="copy-report" onClick={copyReport}>{copied ? <Check size={16}/> : <Clipboard size={16}/>} {copied ? 'Copied' : 'Copy report'}</button>}</div>
        {!finding ? <div className="empty-results"><div className="empty-icon"><Fingerprint size={31} strokeWidth={1.3}/></div><div><h3>Nothing to report. Yet.</h3><p>Run a scan to see potential vulnerabilities, evidence from the AST verifier, and practical next steps.</p></div><span className="empty-ref">AWAITING INPUT / 000</span></div> : <div className="report">
          <div className="report-overview"><div className="report-summary"><span className="eyebrow">SCAN SUMMARY</span><p>{finding.summary}</p></div><div className="report-numbers"><div><strong>{String(total).padStart(2,'0')}</strong><span>Potential findings</span></div><div><strong>{String(staticCount).padStart(2,'0')}</strong><span>AST patterns</span></div></div></div>
          <div className="report-tabs" role="tablist" aria-label="Report views"><button type="button" role="tab" aria-selected={tab==='findings'} className={tab==='findings'?'selected':''} onClick={()=>setTab('findings')}>Findings <span>{total}</span></button><button type="button" role="tab" aria-selected={tab==='evidence'} className={tab==='evidence'?'selected':''} onClick={()=>setTab('evidence')}>AST evidence <span>{staticCount}</span></button></div>
          {tab==='findings' ? (total ? <div className="finding-list">{finding.findings.map((item,i)=><Finding item={item} index={i} key={`${item.category}-${item.line}-${i}`} onGeneratePatch={generatePatch} patchLoading={patchLoading || loading}/>)}</div> : <div className="zero-state"><Check size={20}/><div><strong>No findings reported.</strong><p>This scan did not identify issues. It does not prove the code is secure.</p></div></div>) : <div className="evidence-list">{finding.verification?.status==='error' ? <p className="evidence-error">{finding.verification.message}</p> : staticCount ? finding.verification.evidence.map((item,i)=><div className="evidence-row" key={i}><span className="evidence-num">{String(i+1).padStart(2,'0')}</span><strong>{item.category}</strong><span>Line {item.line}</span><p>{item.description}</p></div>) : <div className="zero-state"><Check size={20}/><div><strong>No AST patterns found.</strong><p>Only the currently implemented static checks were evaluated.</p></div></div>}</div>}
          <div className="report-disclaimer"><CircleAlert size={15}/> Findings are potential issues. Static evidence is not proof of exploitability.</div>
        </div>}
      </section>
      {(patch || patchLoading || patchError) && (
        <section className="patch-section" id="patch-review" aria-label="Suggested patch review">
          <div className="section-heading">
            <div><span className="eyebrow">03 / PROPOSED REPAIR</span><h2>Review the fix.</h2></div>
            <span className="section-side">{patchFinding?.category || 'Python'} <span className="mid-dot">/</span> Line {patchFinding?.line ?? '—'}</span>
          </div>
          {patchLoading && <div className="patch-message" role="status"><LoaderCircle size={18} className="spin"/> Generating and checking the proposed patch…</div>}
          {patchError && <div className="error-banner" role="alert"><CircleAlert size={18}/><span>{patchError}</span></div>}
          {scanSource === vulnerable && <div className="reviewed-repair-offer">
            <p><strong>Reviewed demo repair:</strong> Load a pre-reviewed arithmetic parser that preserves calculator functionality, then approve and test the displayed code in CreateOS.</p>
            <button type="button" className="generate-patch-button" disabled={patchLoading} onClick={loadReviewedRepair}>Load reviewed calculator repair</button>
          </div>}
          {patch && <>
            <div className="patch-status">
              <strong>{patch.status === 'needs_revision' ? 'Needs revision' : 'Proposed fix — review required'}</strong>
              <span>{patch.patternRemoved === true ? 'Selected AST pattern not detected in the patch' : 'Selected AST pattern remains or could not be cleared'}</span>
            </div>
            <div className="patch-comparison">
              <div className="patch-code-panel"><div className="patch-panel-heading"><span>01 / ORIGINAL</span><strong>Before</strong></div><pre><code>{patchSource}</code></pre></div>
              <div className="patch-code-panel"><div className="patch-panel-heading"><span>02 / SUGGESTED</span><strong>After</strong></div><pre><code>{patch.patchedCode}</code></pre></div>
            </div>
            <div className="patch-explanation">
              <span className="eyebrow">REPAIR NOTES</span>
              <p>{patch.explanation}</p>
              {Array.isArray(patch.changes) && patch.changes.length > 0 && <ul>{patch.changes.map((change, i) => <li key={i}>{change}</li>)}</ul>}
              {patch.limitations && <p><strong>Limitations:</strong> {patch.limitations}</p>}
              {patch.remainingPatterns?.length > 0 && <div className="patch-warning"><CircleAlert size={18}/><span>AST verification still detected {patch.remainingPatterns.map(item => `${item.category} at line ${item.line}`).join(', ')}.</span></div>}
              {patch.source && <p><strong>Repair origin:</strong> {patch.source === 'developer_reviewed_template' ? 'Developer-reviewed template (not Gemini-generated)' : patch.source}</p>}
              {patch.patchId && <div className="reviewed-test-controls">
                <label><input type="checkbox" checked={patchTestApproval} disabled={patchTestBusy || !!patchTestResult} onChange={e => setPatchTestApproval(e.target.checked)}/> I reviewed this exact repair and approve running the four demo tests in CreateOS.</label>
                <button className="generate-patch-button" type="button" disabled={!patchTestApproval || patchTestBusy || !!patchTestResult} onClick={testDisplayedRepair}>
                  {patchTestBusy ? 'Testing in CreateOS…' : 'Test this displayed repair'}
                </button>
                {patchTestError && <p role="alert">{patchTestError}</p>}
                {patchTestResult && <div className="sandbox-result" role="status">
                  <strong>{patchTestResult.behaviorTests?.passed ? 'Displayed repair passed' : 'Displayed repair failed'}</strong>
                  <p>Exit code: {String(patchTestResult.behaviorTests?.exitCode ?? 'unknown')}</p>
                  <pre>{patchTestResult.behaviorTests?.stdout || '(no stdout)'}</pre>
                  {patchTestResult.behaviorTests?.stderr && <pre>{patchTestResult.behaviorTests.stderr}</pre>}
                  <p>{patchTestResult.note}</p>
                </div>}
              </div>}
              <p className="patch-disclaimer">{patchTestResult ? "Four narrow behavioral checks were run in CreateOS on this reviewed repair. This is not proof of overall security; other vulnerabilities remain." : "Static checks only. This patch has not been executed, behavior-tested, or approved. Passing a static check does not prove it is secure."}</p>
            </div>
          </>}
        </section>
      )}
      
      <section className="method" id="how-it-works"><div><span className="eyebrow">04 / THE METHOD</span><h2>Three layers.<br/><em>One clearer verdict.</em></h2></div><div className="method-steps"><div><span>01</span><div><h3>AI reads the intent.</h3><p>Gemini explains suspicious behavior and suggests changes in plain language.</p></div><Code2 size={19}/></div><div><span>02</span><div><h3>AST checks the structure.</h3><p>Deterministic Python rules flag supported patterns without running submitted code.</p></div><GitCompareArrows size={19}/></div><div><span>03</span><div><h3>CreateOS tests the reviewed repair.</h3><p>Approved demo code runs inside an isolated sandbox, with actual test results and clearly stated limitations.</p></div><ShieldCheck size={19}/></div></div></section>
    </main>
    <footer className="site-footer"><a className="brand footer-brand" href="#top"><span className="brand-symbol"><ShieldCheck size={17}/></span>agentguard<span className="brand-period">.</span></a><span>Built for people who read code carefully.</span><span>LOCAL WORKBENCH / 2026</span></footer>
  </div>;
}
