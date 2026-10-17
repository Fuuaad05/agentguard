
import "dotenv/config";
import fs from "node:fs/promises";
import crypto from "node:crypto";
import { GoogleGenAI } from "@google/genai";
import { createClient } from "@nodeops-createos/sandbox";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});

const createos = createClient();

const sourceCode = `
def calculate(expression):
    return eval(expression)
`;

const testFile = "pending-test.json";

async function generateTest() {
  console.log("AgentGuard: AI analysis started...");

  const response = await ai.models.generateContent({
    model: process.env.GEMINI_MODEL,
    contents: `
You are AgentGuard, a defensive code security agent.

Analyze this deliberately vulnerable Python code:

${sourceCode}

Identify the security risk and generate one harmless
Python verification test.

Rules:
- Standard library only.
- No filesystem, network, subprocess, or environment access.
- No destructive operations.
- Test only simple arithmetic expression evaluation.
- Use assertions to verify the expected behavior.
- Print TEST PASSED only after all assertions succeed.
- Never catch or suppress AssertionError or unexpected exceptions.
- A failed test must exit with a nonzero exit code.
- The function calculate(expression) is provided by the test harness.
- Do not redefine calculate().
- Only use harmless arithmetic expressions.
- Return JSON with exactly these string fields:
  title, severity, explanation, test_code, recommendation.
- Return only JSON, without markdown fences.
`,
    config: {
      responseMimeType: "application/json",
      temperature: 0.2
    }
  });

  const finding = JSON.parse(response.text);

  for (const key of [
    "title", "severity", "explanation",
    "test_code", "recommendation"
  ]) {
    if (typeof finding[key] !== "string") {
      throw new Error(`Invalid response field: ${key}`);
    }
  }

  const hash = crypto
    .createHash("sha256")
    .update(finding.test_code)
    .digest("hex");

  await fs.writeFile(
    testFile,
    JSON.stringify({ finding, hash }, null, 2)
  );

  console.log("\n=== AGENTGUARD FINDING ===");
  console.log("Title:", finding.title);
  console.log("Severity:", finding.severity);
  console.log("Explanation:", finding.explanation);
  console.log("\nGenerated test:\n");
  console.log(finding.test_code);
  console.log("\nSuggested fix:", finding.recommendation);

  console.log("\nReview pending-test.json carefully.");
  console.log("Then run: node agentguard-v2.js --run");
}

async function runApprovedTest() {
  const saved = JSON.parse(
    await fs.readFile(testFile, "utf8")
  );

  const code = saved.finding.test_code;

  const hash = crypto
    .createHash("sha256")
    .update(code)
    .digest("hex");

  if (hash !== saved.hash) {
    throw new Error("Test changed since generation.");
  }

  console.log("Executing saved test in CreateOS...");

  let sandbox;

  try {
    sandbox = await createos.createSandbox({
      shape: "s-1vcpu-1gb",
      rootfs: "devbox:1"
    });

    const combinedCode = [
        sourceCode.trim(),
        code.trim(),
    ].join("\n\n");

    const syntaxCheck = await sandbox.runCommand(
        "python3",
    [   "-c", "import ast,sys; ast.parse(sys.argv[1]); print('Syntax valid')", combinedCode]
    );

    if (syntaxCheck.result.exit_code !== 0) {
        throw new Error(
            `Generated Python has invalid syntax:\n${syntaxCheck.result.stderr}`
        );
    }

    const result = await sandbox.runCommand(
      "python3",
      ["-I", "-c", combinedCode]
    );

    console.log("\n=== TEST OUTPUT ===");
    console.log(result.result.stdout);
    console.log(result.result.stderr || "");

    console.log(
      "\nNote: Review output before marking a finding verified."
    );
  } finally {
    if (sandbox) {
      await sandbox.destroy();
      console.log("Sandbox cleaned up.");
    }
  }
}

const mode = process.argv[2];

if (mode === "--run") {
  await runApprovedTest();
} else {
  await generateTest();
}
