
# AgentGuard

**Find the flaw. Understand the fix.**

AgentGuard is an AI-powered Python security review and repair workbench built for the **CreateOS × Stripe Projects Hackathon 2026**.

It combines Google's Gemini AI with independent Python AST analysis to identify potential vulnerabilities, explain security risks, generate targeted code repairs, and execute approved AI-generated patches inside a CreateOS Sandbox.

Unlike a traditional static scanner, AgentGuard demonstrates a human-approved agent workflow:

**Analyze → Detect → Generate → Verify → Approve → Execute → Test → Revise**

The goal is simple: help developers understand vulnerable code, review AI-generated fixes, and observe how those fixes behave when executed in an isolated environment.

> **Demo scope:** AgentGuard's live AI execution workflow is restricted to a bundled Python calculator example. AI-generated candidates require explicit human approval before execution. This prototype is not a production-grade sandbox security system and must not be exposed as a public arbitrary-code execution service.

---

## Features

### 1. AI-Powered Vulnerability Analysis

AgentGuard uses Gemini to analyze Python source code and identify potential security weaknesses.

For each finding, the interface displays:

- Vulnerability title and severity
- CWE classification and affected line
- Explanation of the potential risk
- Recommended remediation
- Suggested verification steps
- Confidence and evidence status

AI-generated findings are presented as potential vulnerabilities, not confirmed exploits.

### 2. Independent Python AST Verification

AgentGuard uses a Python-based AST verifier to detect supported code patterns without executing the submitted source.

Currently supported checks include:

| CWE | Vulnerability | Detection scope |
|-----|---------------|-----------------|
| CWE-94 | Code injection | Direct use of `eval()` |
| CWE-89 | SQL injection | Selected unsafe SQL string-construction patterns |
| CWE-798 | Hardcoded credentials | Selected hardcoded-password comparison patterns |

The verifier provides independent structural evidence alongside Gemini's analysis.

These checks are intentionally limited and do not constitute a comprehensive security audit.

### 3. AI-Generated Security Repairs

Gemini generates a targeted replacement for vulnerable Python code.

AgentGuard displays:

- Original source code
- AI-generated replacement
- Explanation of the proposed changes
- Targeted AST verification results
- Remaining detected patterns
- Limitations of the proposed repair

A generated repair is never assumed to be secure simply because it removes a known vulnerable pattern.

### 4. Human-Approved Agent Execution

AgentGuard includes a live AI repair workflow for the bundled vulnerable calculator example.

The process works as follows:

1. The user scans the vulnerable Python example.
2. Gemini generates a candidate repair.
3. AgentGuard performs targeted AST checks.
4. The generated Python code is displayed for review.
5. The user explicitly approves the candidate.
6. AgentGuard sends the approved candidate to a CreateOS Sandbox.
7. The sandbox executes the candidate with regression tests.
8. AgentGuard displays the actual execution output, exit code, and test status.

Every generated candidate requires approval before execution.

### 5. Regression Testing in CreateOS

The updated agent workflow runs seven targeted regression checks against the approved calculator repair.

These checks cover supported arithmetic behavior and selected invalid or unsafe inputs.

The interface reports:

- Test pass/fail status
- Process exit code
- Standard output
- Standard error
- Execution history

The tests assess a limited calculator implementation, not the security of the complete Python program.

### 6. AI-Assisted Repair Revisions

If a candidate fails the regression tests, AgentGuard can provide the failure output to Gemini and request a revised patch.

The revised candidate is displayed for another review and approval.

AgentGuard limits the demonstration workflow to two candidate attempts.

**Revised code is not executed automatically without separate approval.**

### 7. Developer-Reviewed Repair Demo

AgentGuard also retains a separate developer-reviewed repair workflow.

This demonstration uses a predefined arithmetic parser, an explicit approval step, and four narrow calculator behavior tests executed in CreateOS.

This path is distinct from the Gemini-generated agent execution workflow.

---

## Demo Results

During local testing, AgentGuard successfully completed the AI-generated repair workflow.

| Stage | Result |
|-------|--------|
| Gemini generated a Python repair | Successful |
| Targeted CWE-94 AST pattern removed | Confirmed by static check |
| Human approval | Granted |
| AI-generated Python executed in CreateOS | Successful |
| Agent regression checks | Passed |
| Sandbox process exit code | `0` |

Actual execution output:

```text
AGENT REGRESSION TESTS PASSED
```

The separate developer-reviewed repair workflow also passed its four approved calculator tests.

**Important:** Passing these tests does not prove that the entire application is secure. The bundled example still contains separate SQL injection and hardcoded-password issues that are not repaired by the targeted calculator fix.

---

## Architecture

```text
                  AGENTGUARD
             React + Vite Frontend
               localhost:5173
                      |
                      v
               Express Backend
               localhost:3001
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       Gemini AI   Python AST   CreateOS Sandbox
          |         Verifier        ^
          |           |             |
          v           v             |
     AI Analysis   Structural       |
     and Repairs   Verification     |
          |           |             |
          +-----+-----+             |
                |                   |
                v                   |
          Candidate Review          |
                |                   |
                v                   |
          Human Approval -----------+
                                    |
                                    v
                             Execute Tests
                                    |
                          +---------+---------+
                          |                   |
                        Passed              Failed
                          |                   |
                          v                   v
                     Show Results       Gemini Revision
                                              |
                                              v
                                        New Approval
```

### Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | React, Vite, JavaScript |
| Styling | CSS, Lucide React |
| Backend | Node.js, Express |
| AI | Google Gemini (`@google/genai`) |
| Static verification | Python standard-library `ast` |
| Code execution | CreateOS Sandbox SDK (`@nodeops-createos/sandbox`) |
| Project integration | Stripe Projects |

---

## API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /api/health` | Backend health check |
| `POST /api/analyze` | Gemini-assisted security analysis and AST verification |
| `POST /api/patch` | Generate a suggested AI repair without executing it |
| `POST /api/agent-propose` | Generate an AI repair candidate for the supported demo |
| `POST /api/agent-run` | Execute an explicitly approved candidate in CreateOS |
| `POST /api/reviewed-repair` | Load the separate developer-reviewed demo repair |
| `POST /api/test-reviewed-patch` | Test the approved developer-reviewed repair |

Additional demo endpoints may be present in the backend.

### Agent Execution Boundaries

The `/api/agent-propose` endpoint only accepts the exact bundled calculator demonstration source and the supported CWE-94 category.

The `/api/agent-run` endpoint requires:

- A valid candidate identifier
- Explicit approval
- A candidate that has not already been consumed
- A candidate within its validity period
- Targeted AST verification

These restrictions reduce accidental execution but are **not sufficient to guarantee that generated Python is safe**.

---

## Installation

### Prerequisites

Make sure you have:

- Node.js and npm
- Python 3
- A Google Gemini API key
- Access to CreateOS Sandbox
- Stripe Projects configured for the CreateOS integration

### 1. Clone the Repository

```bash
git clone https://github.com/Fuuaad05/agentguard.git
cd agentguard
```

### 2. Install Dependencies

Install backend dependencies:

```bash
npm install
```

Install frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

### 3. Configure Environment Variables

Create a `.env` file in the project root.

Example:

```dotenv
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=your_supported_gemini_model
CREATEOS_PROJECT_3_API_KEY=your_stripe_projects_createos_key
```

The CreateOS environment variable above corresponds to the Stripe Projects resource used in the hackathon build. If your resource has a different variable name, update the backend configuration accordingly.

**Never commit `.env` files, API keys, or other credentials.**

### 4. Start the Backend

From the project root:

```bash
node --check server.js
node server.js
```

Expected output:

```text
AgentGuard API running at http://localhost:3001
```

### 5. Start the Frontend

Open another terminal:

```bash
cd frontend
npm run dev
```

Open:

http://localhost:5173

Backend health check:

http://localhost:3001/api/health

---

## Live Demo Walkthrough

### Step 1 — Load the Vulnerable Example

Click **Vulnerable example** in the code editor.

The bundled example contains three intentionally vulnerable patterns:

- Unsafe `eval()` usage
- SQL query construction using string interpolation
- Hardcoded password comparison

### Step 2 — Run Security Analysis

Click **Run security scan**.

AgentGuard displays Gemini's analysis, supported AST evidence, severity information, and remediation suggestions.

### Step 3 — Generate an AI Repair

Navigate to **Live Agent Execution**.

Click **Generate AI repair**.

Gemini writes a replacement for the vulnerable calculator function.

### Step 4 — Review the Generated Code

Inspect the original and generated Python code side by side.

Review the explanation, changes, and targeted static verification status.

### Step 5 — Approve Execution

After reviewing the exact generated candidate, select the approval checkbox.

Click **Approve & run in CreateOS**.

### Step 6 — Inspect Execution Results

AgentGuard executes the approved candidate inside CreateOS and displays:

- Regression-test result
- Exit code
- Standard output
- Standard error
- Execution history

A successful local run displayed:

```text
AGENT REGRESSION TESTS PASSED
```

### Step 7 — Review a Revision if Necessary

If a candidate fails, AgentGuard can request a revised patch from Gemini using the failure feedback.

The revised code must be reviewed and approved separately.

---

## Screenshots

### Security Workbench

![AgentGuard Workbench](screenshots/workbench.png)

### Vulnerability Detection

![AgentGuard Security Findings](screenshots/findings.png)

### CreateOS Sandbox Testing

![AgentGuard CreateOS Test Success](screenshots/createos-test-success.png)

> Screenshot paths assume the corresponding images are committed to the repository's `screenshots/` directory.

---

## Security Limitations

AgentGuard is an experimental hackathon prototype with important limitations.

1. **Limited AST coverage:** The verifier only recognizes selected Python patterns. It can miss vulnerabilities or report false positives.

2. **AI output is not inherently trustworthy:** Gemini-generated code may contain logic errors, incomplete fixes, or unsafe behavior.

3. **Restricted execution scope:** The live execution endpoint supports the bundled demonstration example, not arbitrary submitted Python projects.

4. **Human approval is required:** Approval gates execution but does not independently guarantee code safety.

5. **Limited behavioral testing:** Passing seven regression checks does not establish comprehensive correctness, security, or compatibility.

6. **Incomplete isolation policy:** The prototype has not established production-grade controls for arbitrary generated code, including comprehensive execution restrictions, network isolation, and resource limits.

7. **Remaining vulnerabilities:** The targeted calculator repair does not resolve the separate SQL injection or hardcoded-password patterns.

8. **Local development:** The backend is intended for controlled local demonstration and should not be exposed as a public code execution service.

Use AgentGuard only on code you own or are authorized to review.

---

## Project Structure

```text
agentguard/
├── server.js                 # Express API, Gemini, CreateOS execution
├── verifier.py               # Python AST pattern verification
├── frontend/
│   └── src/
│       ├── App.jsx           # Security workbench and agent interface
│       └── App.css           # Frontend styling
├── screenshots/
│   ├── workbench.png
│   ├── findings.png
│   └── createos-test-success.png
├── README.md
└── .env                      # Local credentials (not committed)
```

---

## Hackathon

Built for the **CreateOS × Stripe Projects — Build Agents That Run Code Hackathon**, October 17, 2026.

AgentGuard demonstrates how an AI agent can identify a targeted code weakness, write a proposed repair, execute approved generated code in CreateOS, inspect regression-test feedback, and propose a revision when a test fails.

**GitHub:** https://github.com/Fuuaad05/agentguard

**CreateOS:** https://createos.sh

**Stripe Projects:** https://projects.dev

---

## Future Improvements

- Broader Python vulnerability detection
- Stronger generated-code validation before sandbox execution
- Resource and network restrictions for sandbox workloads
- More comprehensive regression and security tests
- Multi-file project analysis
- Additional vulnerability-specific repair workflows
- Automated comparison of security findings before and after a patch
- Expanded agent execution history and audit trails

---

## Responsible Use

AgentGuard is intended for security education, code review assistance, and controlled experimentation.

It is not a replacement for professional security assessments, secure development practices, or independent verification of AI-generated code.

**Built to make AI-assisted code security more understandable, testable, and transparent.**
