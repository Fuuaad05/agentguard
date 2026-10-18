import { useState } from 'react';
import { ArrowUpRight, ArrowRight, Check, ChevronDown, ChevronUp, CircleAlert, Clipboard, Code2, FileCode2, Fingerprint, GitCompareArrows, LoaderCircle, ScanLine, ShieldCheck, X, Play, RefreshCw } from 'lucide-react';
import './App.css';

const API = (
  import.meta.env.VITE_API_URL || 'http://localhost:3001'
).replace(/\/+$/, '');
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
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()`;
const severityClass = s => (s || 'unrated').toLowerCase().replace(/[^a-z]/g, '');
const statusText = { static_pattern_confirmed: 'Supported by AST pattern evidence', static_only: 'AST-only detection · review required', ai_only: 'AI-only assessment · review required' };
async function post(path, payload) {
  const response = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  let data;
  try { data = await response.json(); } catch { throw new Error(`Invalid API response (${response.status})`); }
  if (!response.ok) throw new Error(data.error || data.message || `Request failed (${response.status})`);
  return data;
}
function CodeLines({ code }) { return <div className="code-lines" aria-hidden="true">{code.split('\n').map((_, i) => <span key={i}>{i + 1}</span>)}</div>; }
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
      <div className="finding-detail-grid"><div><span className="eyebrow">RECOMMENDED FIX</span><p>{item.recommendation}</p></div><div><span className="eyebrow">HOW TO CHECK</span><p>{item.verification}</p></div></div>
      <div className="finding-foot"><span className="evidence-dot"/>{statusText[item.verificationStatus] || 'Potential finding · not exploit-verified'} <span className="confidence">Confidence: {item.confidence || '—'}</span></div>
      {/^CWE-\d{1,5}$/.test(item.category || '') && Number.isInteger(item.line) && item.line > 0 && <div className="finding-patch-action"><button type="button" className="generate-patch-button" disabled={patchLoading} onClick={() => onGeneratePatch(item)}>{patchLoading ? <LoaderCircle size={16} className="spin"/> : <GitCompareArrows size={16}/>} {patchLoading ? 'Generating fix…' : 'Generate suggested fix'} <ArrowUpRight size={15}/></button></div>}
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
  const [agent, setAgent] = useState(null);
  const [agentSource, setAgentSource] = useState('');
  const [agentError, setAgentError] = useState('');
  const [agentBusy, setAgentBusy] = useState(false);
  const [agentApproved, setAgentApproved] = useState(false);
  const [agentRun, setAgentRun] = useState(null);
  const [agentHistory, setAgentHistory] = useState([]);
  const busy = loading || patchLoading || patchTestBusy || agentBusy;
  function resetAgent() { setAgent(null); setAgentSource(''); setAgentError(''); setAgentApproved(false); setAgentRun(null); setAgentHistory([]); }
  function clearPatch() { setPatch(null); setPatchError(''); setPatchFinding(null); setPatchSource(''); setPatchTestApproval(false); setPatchTestResult(null); setPatchTestError(''); }
  function updateCode(next) { if (busy) return; setCode(next); setFinding(null); setScanSource(''); setError(''); clearPatch(); resetAgent(); }
  async function analyze() {
    if (busy || !code.trim()) return;
    setLoading(true); setFinding(null); setScanSource(''); setError(''); setTab('findings'); clearPatch(); resetAgent();
    try { const data = await post('/api/analyze', { code }); if (!Array.isArray(data.findings)) throw new Error('Unexpected scanner response.'); setScanSource(code); setFinding(data); }
    catch (e) { setError(e.message || 'Unable to connect to the scanner.'); }
    finally { setLoading(false); }
  }
  async function generatePatch(item) {
    if (busy || !finding || !scanSource) return;
    setPatchLoading(true); setPatch(null); setPatchError(''); setPatchFinding(item); setPatchSource(scanSource); setPatchTestApproval(false); setPatchTestResult(null); setPatchTestError('');
    try { const data = await post('/api/patch', { code: scanSource, category: item.category, line: item.line }); if (!data.patchedCode?.trim()) throw new Error('Invalid patch response.'); setPatch(data); }
    catch (e) { setPatchError(e.message); } finally { setPatchLoading(false); }
  }
  async function loadReviewedRepair() {
    if (busy || !scanSource) return;
    setPatchLoading(true); setPatch(null); setPatchError(''); setPatchSource(scanSource); setPatchFinding({ category: 'CWE-94', line: 4 }); setPatchTestApproval(false); setPatchTestResult(null); setPatchTestError('');
    try { setPatch(await post('/api/reviewed-repair', { code: scanSource, category: 'CWE-94' })); }
    catch (e) { setPatchError(e.message); } finally { setPatchLoading(false); }
  }
  async function testDisplayedRepair() {
    if (!patch?.patchId || !patchTestApproval || busy || patchTestResult) return;
    setPatchTestBusy(true); setPatchTestResult(null); setPatchTestError('');
    try { setPatchTestResult(await post('/api/test-reviewed-patch', { patchId: patch.patchId, approved: true })); }
    catch (e) { setPatchTestError(e.message); } finally { setPatchTestBusy(false); }
  }
  async function proposeAgent() {
    if (busy || !scanSource) return;
    setAgentBusy(true); resetAgent(); setAgentSource(scanSource);
    try { const data = await post('/api/agent-propose', { code: scanSource, category: 'CWE-94' }); setAgent(data); }
    catch (e) { setAgentError(e.message); } finally { setAgentBusy(false); }
  }
  async function executeAgent() {
    if (busy || !agent?.candidateId || agent.status !== 'awaiting_approval' || !agentApproved || agentRun) return;
    setAgentBusy(true); setAgentError('');
    try {
      const data = await post('/api/agent-run', { candidateId: agent.candidateId, approved: true });
      setAgentRun(data);
      setAgentHistory(prev => [...prev, { candidate: agent, result: data }]);
    } catch (e) { setAgentError(e.message); } finally { setAgentBusy(false); }
  }
  function inspectRevision() {
    if (!agentRun?.revision?.candidateId) return;
    setAgent(agentRun.revision); setAgentApproved(false); setAgentRun(null); setAgentError('');
  }
  async function copyReport() {
    if (!finding) return;
    const text = ['AgentGuard security review', finding.summary, '', ...finding.findings.map((f, i) => `${i + 1}. ${f.title} [${f.severity}] ${f.category} line ${f.line}\n${f.explanation}\nFix: ${f.recommendation}\nStatus: ${statusText[f.verificationStatus] || 'Potential'}`)].join('\n');
    try { await navigator.clipboard.writeText(text); setCopied(true); window.setTimeout(() => setCopied(false), 1800); } catch { setError('Could not copy report.'); }
  }
  const total = finding?.findings?.length ?? 0;
  const staticCount = finding?.verification?.evidence?.length ?? 0;
  const agentEligible = !!scanSource && scanSource === vulnerable;
  return <div className="site-shell">
    <div className="top-rule"/>
    <header className="site-header"><a className="brand" href="#top"><span className="brand-symbol"><ShieldCheck size={20}/></span>agentguard<span className="brand-period">.</span></a><nav className="top-nav"><a href="#workspace" className="nav-selected">Workbench</a><a href="#how-it-works">Method</a><a href="#results">Results</a><a href="#agent-workflow">Live agent</a></nav><span className="header-label"><span className="live-dot"/> LOCAL BUILD <span className="header-version">/ v0.4</span></span></header>
    <main id="top">
      <section className="intro"><div className="intro-top"><span className="eyebrow"><span className="eyebrow-mark">/</span> CODE SECURITY WORKBENCH</span><span className="edition">01 — PYTHON ANALYSIS</span></div><div className="intro-content"><div><h1>Find the flaw.<br/><em>Understand the fix.</em></h1><p>Inspect Python code, review the evidence, and watch an AI agent propose and test a targeted repair in CreateOS.</p><a className="intro-link" href="#workspace">Go to the workbench <ArrowRight size={17}/></a></div><div className="intro-side"><span className="intro-side-num">AG—01</span><p>Gemini-assisted review<br/>Independent AST checks<br/>Human-approved execution.</p></div></div></section>
      <section className="workbench" id="workspace"><div className="section-heading"><div><span className="eyebrow">01 / THE WORKBENCH</span><h2>Inspect your code.</h2></div><span className="section-side">Python / Gemini + AST</span></div><div className="editor-shell"><div className="editor-toolbar"><div className="file-name"><FileCode2 size={16}/> review.py <span className="file-tag">PYTHON</span></div><div className="editor-actions"><button onClick={() => updateCode(vulnerable)}>Vulnerable example</button><span className="toolbar-divider"/><button onClick={() => updateCode(safe)}>Safer example</button><button className="icon-button" onClick={() => updateCode('')} title="Clear editor"><X size={16}/></button></div></div><div className="editor-body"><CodeLines code={code}/><textarea aria-label="Python source code" spellCheck="false" value={code} disabled={busy} onChange={e => updateCode(e.target.value)} placeholder="# Paste Python code to inspect..."/></div><div className="editor-footer"><span><span className="footer-square"/> {code.split('\n').length} lines · Code is sent to your configured analysis API</span><button className="scan-button" disabled={busy || !code.trim()} onClick={analyze}>{loading ? <LoaderCircle size={17} className="spin"/> : <ScanLine size={17}/>} {loading ? 'Reviewing code…' : 'Run security scan'} <ArrowUpRight size={16}/></button></div></div>{error && <div className="error-banner" role="alert"><CircleAlert size={18}/>{error}<button onClick={() => setError('')}><X size={17}/></button></div>}</section>
      <section className="results-section" id="results"><div className="section-heading"><div><span className="eyebrow">02 / REVIEW OUTPUT</span><h2>The findings.</h2></div>{finding && <button className="copy-report" onClick={copyReport}>{copied ? <Check size={16}/> : <Clipboard size={16}/>} {copied ? 'Copied' : 'Copy report'}</button>}</div>
        {!finding ? <div className="empty-results"><div className="empty-icon"><Fingerprint size={31}/></div><div><h3>Nothing to report. Yet.</h3><p>Run a scan to see potential vulnerabilities, AST evidence, and practical next steps.</p></div><span className="empty-ref">AWAITING INPUT / 000</span></div> : <div className="report"><div className="report-overview"><div className="report-summary"><span className="eyebrow">SCAN SUMMARY</span><p>{finding.summary}</p></div><div className="report-numbers"><div><strong>{String(total).padStart(2, '0')}</strong><span>Potential findings</span></div><div><strong>{String(staticCount).padStart(2, '0')}</strong><span>AST patterns</span></div></div></div><div className="report-tabs" role="tablist"><button role="tab" aria-selected={tab === 'findings'} className={tab === 'findings' ? 'selected' : ''} onClick={() => setTab('findings')}>Findings <span>{total}</span></button><button role="tab" aria-selected={tab === 'evidence'} className={tab === 'evidence' ? 'selected' : ''} onClick={() => setTab('evidence')}>AST evidence <span>{staticCount}</span></button></div>{tab === 'findings' ? (total ? <div className="finding-list">{finding.findings.map((item, i) => <Finding item={item} index={i} key={`${item.category}-${item.line}-${i}`} onGeneratePatch={generatePatch} patchLoading={busy}/>)}</div> : <div className="zero-state"><Check size={20}/> No findings reported. This does not prove security.</div>) : <div className="evidence-list">{finding.verification?.status === 'error' ? <p className="evidence-error">{finding.verification.message}</p> : staticCount ? finding.verification.evidence.map((item, i) => <div className="evidence-row" key={i}><span className="evidence-num">{String(i + 1).padStart(2, '0')}</span><strong>{item.category}</strong><span>Line {item.line}</span><p>{item.description}</p></div>) : <div className="zero-state"><Check size={20}/> No supported AST patterns found.</div>}</div>}<div className="report-disclaimer"><CircleAlert size={15}/> Findings are potential issues. Static evidence is not proof of exploitability.</div></div>}
      </section>
      <section className="agent-section" id="agent-workflow"><div className="section-heading"><div><span className="eyebrow">03 / LIVE AGENT EXECUTION</span><h2>From flaw to tested fix.</h2></div><span className="section-side">Gemini / CreateOS Sandbox</span></div><div className="agent-intro"><div><strong>Let the agent write the repair.</strong><p>For the bundled calculator demo, Gemini writes a patch, AST checks inspect the targeted pattern, you approve execution, and CreateOS runs regression tests. Failed runs can produce a revised candidate.</p></div><button type="button" className="scan-button" disabled={busy || !agentEligible} onClick={proposeAgent}>{agentBusy && !agent ? <LoaderCircle size={17} className="spin"/> : <Code2 size={17}/>} {agentBusy && !agent ? 'Generating candidate…' : 'Generate AI repair'} <ArrowUpRight size={15}/></button></div>{!agentEligible && <p className="agent-hint">This execution workflow is currently limited to the exact bundled vulnerable example. Load that example and run the security scan first.</p>}
        {agentError && <div className="error-banner" role="alert"><CircleAlert size={18}/>{agentError}</div>}
        {agentHistory.length > 0 && <div className="agent-history"><span className="eyebrow">EXECUTION HISTORY</span>{agentHistory.map((entry, i) => <div key={i} className="history-row"><span>Attempt {entry.candidate.attempt ?? i + 1}</span><strong>{entry.result.behaviorTests?.passed ? 'Passed' : 'Failed'}</strong><span>Exit {String(entry.result.behaviorTests?.exitCode ?? '—')}</span></div>)}</div>}
        {agent && <div className="agent-review"><div className="patch-status"><strong>{agent.status === 'awaiting_approval' ? 'AI-generated candidate · awaiting approval' : agent.status || 'Candidate returned'}</strong><span>Attempt {agent.attempt ?? '—'} · CWE-94 pattern removed: {String(agent.patternRemoved === true)}</span></div><div className="patch-comparison"><div className="patch-code-panel"><div className="patch-panel-heading"><span>01 / ORIGINAL</span><strong>Before</strong></div><pre><code>{agentSource}</code></pre></div><div className="patch-code-panel"><div className="patch-panel-heading"><span>02 / GEMINI GENERATED</span><strong>Candidate</strong></div><pre><code>{agent.patchedCode || '(No patch returned)'}</code></pre></div></div><div className="patch-explanation"><span className="eyebrow">CANDIDATE REVIEW</span>{agent.explanation && <p>{agent.explanation}</p>}{Array.isArray(agent.changes) && agent.changes.length > 0 && <ul>{agent.changes.map((change, i) => <li key={i}>{change}</li>)}</ul>}<p className="patch-disclaimer">Static pattern removal is not a security guarantee. The candidate may contain errors or unsafe behavior. Only approve this controlled demonstration after reviewing the exact generated code.</p>{agent.status === 'awaiting_approval' && !agentRun && <div className="reviewed-test-controls"><label><input type="checkbox" checked={agentApproved} disabled={agentBusy} onChange={e => setAgentApproved(e.target.checked)}/> I have reviewed this exact Gemini-generated patch and approve running the demo regression tests in CreateOS.</label><button className="generate-patch-button" type="button" disabled={!agentApproved || agentBusy} onClick={executeAgent}>{agentBusy ? <LoaderCircle size={16} className="spin"/> : <Play size={16}/>} {agentBusy ? 'Executing in CreateOS…' : 'Approve & run in CreateOS'}</button></div>}</div></div>}
        {agentRun && <div className="agent-output"><div className="agent-output-head"><strong>{agentRun.behaviorTests?.passed ? 'Regression tests passed' : 'Regression tests failed'}</strong><span>Exit code {String(agentRun.behaviorTests?.exitCode ?? 'unknown')}</span></div><div className="terminal-title">CREATEOS / EXECUTION OUTPUT</div><pre>{agentRun.behaviorTests?.stdout || '(no stdout)'}{agentRun.behaviorTests?.stderr ? `\n${agentRun.behaviorTests.stderr}` : ''}</pre>{agentRun.revision?.candidateId && <div className="revision-action"><p>Gemini proposed a revised candidate after the failed test. Review it before any further execution.</p><button className="generate-patch-button" onClick={inspectRevision}><RefreshCw size={16}/> Review agent revision</button></div>}{agentRun.revisionError && <p role="alert">Revision error: {agentRun.revisionError}</p>}<p className="patch-disclaimer">Passing these limited calculator tests does not establish overall code security. Other vulnerabilities in the original sample remain.</p></div>}
      </section>
      {(patch || patchLoading || patchError) && <section className="patch-section" id="patch-review"><div className="section-heading"><div><span className="eyebrow">04 / SUGGESTED REPAIR</span><h2>Review the fix.</h2></div><span className="section-side">{patchFinding?.category || 'Python'} / Line {patchFinding?.line ?? '—'}</span></div>{patchLoading && <div className="patch-message"><LoaderCircle className="spin" size={18}/> Generating and checking the proposed patch…</div>}{patchError && <div className="error-banner" role="alert"><CircleAlert size={18}/>{patchError}</div>}{scanSource === vulnerable && <div className="reviewed-repair-offer"><p><strong>Developer-reviewed alternative:</strong> Load a pre-reviewed calculator repair and run its four demo tests. This is not Gemini-generated.</p><button className="generate-patch-button" disabled={busy} onClick={loadReviewedRepair}>Load reviewed calculator repair</button></div>}{patch && <><div className="patch-status"><strong>{patch.status === 'needs_revision' ? 'Needs revision' : 'Proposed fix · review required'}</strong><span>{patch.patternRemoved ? 'Selected AST pattern not detected in patch' : 'Pattern remains or was not cleared'}</span></div><div className="patch-comparison"><div className="patch-code-panel"><div className="patch-panel-heading"><span>01 / ORIGINAL</span><strong>Before</strong></div><pre><code>{patchSource}</code></pre></div><div className="patch-code-panel"><div className="patch-panel-heading"><span>02 / SUGGESTED</span><strong>After</strong></div><pre><code>{patch.patchedCode}</code></pre></div></div><div className="patch-explanation"><span className="eyebrow">REPAIR NOTES</span><p>{patch.explanation}</p>{Array.isArray(patch.changes) && <ul>{patch.changes.map((c, i) => <li key={i}>{c}</li>)}</ul>}{patch.limitations && <p><strong>Limitations:</strong> {patch.limitations}</p>}{patch.remainingPatterns?.length > 0 && <div className="patch-warning"><CircleAlert size={18}/> AST still detected {patch.remainingPatterns.map(i => `${i.category} at line ${i.line}`).join(', ')}</div>}{patch.source && <p><strong>Origin:</strong> {patch.source === 'developer_reviewed_template' ? 'Developer-reviewed template (not Gemini-generated)' : patch.source}</p>}{patch.patchId && <div className="reviewed-test-controls"><label><input type="checkbox" checked={patchTestApproval} disabled={patchTestBusy || !!patchTestResult} onChange={e => setPatchTestApproval(e.target.checked)}/> I reviewed this exact repair and approve running the four demo tests in CreateOS.</label><button className="generate-patch-button" disabled={!patchTestApproval || patchTestBusy || !!patchTestResult} onClick={testDisplayedRepair}>{patchTestBusy ? 'Testing in CreateOS…' : 'Test this displayed repair'}</button>{patchTestError && <p role="alert">{patchTestError}</p>}{patchTestResult && <div className="sandbox-result"><strong>{patchTestResult.behaviorTests?.passed ? 'Displayed repair passed' : 'Displayed repair failed'}</strong><p>Exit code: {String(patchTestResult.behaviorTests?.exitCode ?? 'unknown')}</p><pre>{patchTestResult.behaviorTests?.stdout || '(no stdout)'}</pre>{patchTestResult.behaviorTests?.stderr && <pre>{patchTestResult.behaviorTests.stderr}</pre>}<p>{patchTestResult.note}</p></div>}</div>}<p className="patch-disclaimer">{patchTestResult ? 'Four narrow behavioral checks ran in CreateOS. This does not prove overall security.' : 'Static checks only. This patch has not been executed or behavior-tested.'}</p></div></>}</section>}
      <section className="method" id="how-it-works"><div><span className="eyebrow">05 / THE METHOD</span><h2>Three layers.<br/><em>One clearer verdict.</em></h2></div><div className="method-steps"><div><span>01</span><div><h3>AI reads the intent.</h3><p>Gemini explains suspicious behavior and writes a targeted candidate fix.</p></div><Code2 size={19}/></div><div><span>02</span><div><h3>AST checks the structure.</h3><p>Deterministic rules flag supported patterns without executing submitted source.</p></div><GitCompareArrows size={19}/></div><div><span>03</span><div><h3>CreateOS tests approved code.</h3><p>After human approval, a sandbox runs limited regression tests and reports actual output.</p></div><ShieldCheck size={19}/></div></div></section>
    </main><footer className="site-footer"><a className="brand footer-brand" href="#top"><span className="brand-symbol"><ShieldCheck size={17}/></span>agentguard<span className="brand-period">.</span></a><span>Built for people who read code carefully.</span><span>LOCAL WORKBENCH / 2026</span></footer>
  </div>;
}
