
import "dotenv/config";
import { createClient } from "@nodeops-createos/sandbox";

const client = createClient();

let sandbox;

try {
  console.log("Checking CreateOS authentication...");
  const user = await client.whoami();
  console.log("Authentication successful!");

  console.log("Creating AgentGuard test sandbox...");

  sandbox = await client.createSandbox({
    shape: "s-1vcpu-1gb",
    rootfs: "devbox:1",
  });

  console.log("Sandbox created:", sandbox.id);

  const response = await sandbox.runCommand(
    "python3",
    ["-c", "print('AgentGuard sandbox is working!')"]
  );

  console.log("Output:", response.result.stdout);
} catch (error) {
  console.error("Test failed:", error.message);
  process.exitCode = 1;
} finally {
  if (sandbox) {
    console.log("Cleaning up sandbox...");
    await sandbox.destroy();
  }
}
