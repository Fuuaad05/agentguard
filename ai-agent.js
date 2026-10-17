
import "dotenv/config";
import OpenAI from "openai";
import { createClient } from "@nodeops-createos/sandbox";

const ai = new OpenAI();
const createos = createClient();

const sourceCode = `
def calculate(expression):
    return eval(expression)
`;

async function main() {
  console.log("AgentGuard: Analyzing Python code...");

  const response = await ai.responses.create({
    model: "gpt-4.1-mini",
    instructions: `
You are AgentGuard, a defensive security testing agent.

Analyze only the supplied demonstration code.
Identify one possible security weakness.
Write a harmless Python test using only the standard library.
The test must not access files, networks, environment
variables, subprocesses, or external services.
Do not use destructive or exploit payloads.
The test should print a clear result.
Return only valid JSON with keys:
title, severity, explanation, test_code, recommendation.
`,
    input: `Analyze this Python code:\n${sourceCode}`,
    text: {
      format: {
        type: "json_schema",
        name: "security_test",
        strict: true,
        schema: {
          type: "object",
          properties: {
            title: { type: "string" },
            severity: { type: "string" },
            explanation: { type: "string" },
            test_code: { type: "string" },
            recommendation: { type: "string" }
          },
          required: [
            "title", "severity", "explanation",
            "test_code", "recommendation"
          ],
          additionalProperties: false
        }
      }
    }
  });

  const finding = JSON.parse(response.output_text);

  console.log("\nAI finding:", finding.title);
  console.log("Severity:", finding.severity);
  console.log("Explanation:", finding.explanation);
  console.log("\nGenerated test:\n", finding.test_code);

  // For this prototype, approve generated code manually.
  // Do not execute it automatically yet.
  console.log("\nReview the test before execution.");

  if (!process.argv.includes("--run-approved")) {
    console.log("To execute after review, run:");
    console.log("node ai-agent.js --run-approved");
    return;
  }

  // This checks obvious forbidden operations, but is NOT
  // a security boundary or comprehensive code validator.
  const forbidden = [
    /\bimport\b/,
    /\bopen\s*\(/,
    /\bexec\s*\(/,
    /\beval\s*\(/,
    /\b__import__\b/,
    /\bsubprocess\b/,
    /\bos\./,
    /\bsocket\b/
  ];

  if (forbidden.some(pattern => pattern.test(finding.test_code))) {
    throw new Error("Generated test requires further review.");
  }

  let sandbox;

  try {
    sandbox = await createos.createSandbox({
      shape: "s-1vcpu-1gb",
      rootfs: "devbox:1"
    });

    console.log("\nExecuting in CreateOS...");

    const result = await sandbox.runCommand(
      "python3",
      ["-I", "-c", finding.test_code],
      { timeoutMs: 30000 }
    );

    console.log("STDOUT:", result.result.stdout);
    console.log("STDERR:", result.result.stderr);
    console.log("Exit code:", result.result.exit_code);
    console.log("\nSuggested fix:", finding.recommendation);

  } finally {
    if (sandbox) {
      await sandbox.destroy();
      console.log("Sandbox destroyed.");
    }
  }
}

main().catch(error => {
  console.error("AgentGuard error:", error.message);
  process.exitCode = 1;
});
