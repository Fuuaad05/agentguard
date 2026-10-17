
import "dotenv/config";
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});

async function main() {
  const response = await ai.models.generateContent({
    model: "gemini-3.5-flash-lite",
    contents: `
You are AgentGuard, a defensive cybersecurity assistant.

Analyze this Python code:

def calculate(expression):
    return eval(expression)

Identify the security risk and recommend a safer solution.
Keep your answer brief.
`
  });

  console.log("\n=== AgentGuard AI Analysis ===\n");
  console.log(response.text);
}

main().catch(error => {
  console.error("Gemini error:", error.message);
});
