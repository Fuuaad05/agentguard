
import "dotenv/config";
import { createClient } from "@nodeops-createos/sandbox";

const client = createClient();

// Deliberately vulnerable sample for our demo
const sampleCode = `
def calculate(expression):
    return eval(expression)

print(calculate("2 + 3"))
`;

function analyzePython(code) {
  const findings = [];

  if (/\beval\s*\(/.test(code)) {
    findings.push({
      id: "AG-001",
      title: "Potential unsafe eval() usage",
      severity: "HIGH",
      description:
        "eval() can execute arbitrary Python expressions. " +
        "Using it on untrusted input may allow code execution.",
      recommendation:
        "Avoid eval() for user input. Use a restricted " +
        "expression parser or ast.literal_eval() " +
        "for supported literal values.",
    });
  }

  return findings;
}

async function main() {
  const findings = analyzePython(sampleCode);

  console.log("\n=== AgentGuard Security Scan ===");
  console.log(JSON.stringify(findings, null, 2));

  if (findings.length === 0) {
    console.log("No supported patterns detected.");
    return;
  }

  // A harmless verification test:
  // prove eval evaluates a Python expression.
  const testCode = `
def calculate(expression):
    return eval(expression)

result = calculate("2 * 3 + 1")
assert result == 7
print("TEST PASSED: eval executed the expression")
`;

  const sandbox = await client.createSandbox({
    shape: "s-1vcpu-1gb",
    rootfs: "devbox:1",
  });

  try {
    console.log("\nRunning verification in CreateOS...");

    const encoded = Buffer.from(testCode).toString("base64");

    const result = await sandbox.runCommand(
      "python3",
      [
        "-c",
        "import base64; exec(compile(base64.b64decode('" +
          encoded +
          "'), '<agentguard-test>', 'exec'))",
      ]
    );

    console.log("Sandbox output:");
    console.log(result.result.stdout);
    if (result.result.stderr) {
      console.log(result.result.stderr);
    }
  } finally {
    await sandbox.destroy();
    console.log("Sandbox cleaned up.");
  }
}

main().catch((error) => {
  console.error("AgentGuard error:", error.message);
  process.exitCode = 1;
});
