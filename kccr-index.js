require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const { Anthropic } = require("@anthropic-ai/sdk");

const app = express();
app.use(express.json());

// Initialize Anthropic Client
const anthropic = new Anthropic({
  apiKey:
    process.env.ANTHROPIC_API_KEY ||

});

// Prompt Version identifier for composite cache invalidation
const PROMPT_VERSION = "v1.0.0";

// In-Memory SHA-256 Cache to protect model margins
const RESPONSE_CACHE = new Map();

// --- Refined OWASP Security & Quality System Prompt ---
const SYSTEM_PROMPT = `You are an elite Senior Security Architect and Lead Code Auditor specializing in static code analysis, vulnerability remediation, and software quality assurance.

Conduct a rigorous automated code review and return ONLY a valid, raw JSON object matching the exact schema specified below.

AUDIT RULES:
1. SECURITY & VULNERABILITIES: Check for OWASP Top 10 (SQL Injection, Command Injection, XSS, CSRF, Hardcoded Secrets/Keys, Broken Access Control, Insecure Cryptography, Path Traversal).
2. PERFORMANCE: Identify N+1 queries, memory leaks, blocking I/O, and high algorithmic complexity.
3. ERROR HANDLING: Unhandled exceptions, broad try-catch blocks, missing network timeouts.
4. CODE STYLE: Language anti-patterns, code duplication, poor naming.

OUTPUT JSON SCHEMA (STRICT REQUIREMENT):
Respond with pure JSON only. Do NOT wrap in markdown codeblocks (no \`\`\`json). Do NOT include introductory or conversational text.

The JSON structure MUST strictly adhere to:
{
  "summary": {
    "quality_score": <int 0-100>,
    "pass_build": <boolean>,
    "total_issues": <int>,
    "severity_counts": {
      "critical": <int>,
      "high": <int>,
      "medium": <int>,
      "low": <int>
    }
  },
  "findings": [
    {
      "id": "<CATEGORY-NUMBER, e.g. SEC-001>",
      "category": "<security|performance|style|error_handling>",
      "severity": "<critical|high|medium|low>",
      "title": "<Short, specific title>",
      "line_start": <int 1-indexed>,
      "line_end": <int 1-indexed>,
      "description": "<Detailed explanation of issue>",
      "suggested_fix": "<Ready-to-use refactored code fix>",
      "reference": "<CWE ID or standard reference, e.g. CWE-89 / OWASP Top 10 A03:2021>"
    }
  ]
}

SCORING RULES:
- quality_score starts at 100. Deduct: Critical (-35), High (-20), Medium (-10), Low (-5). Min score is 0.
- pass_build is true ONLY if there are ZERO issues with severity >= fail_threshold (default: 'high').`;

// Helper: Compute SHA-256 Cache Key
function computeCacheKey(language, code, promptVersion = PROMPT_VERSION) {
  const payload = `${language}:${promptVersion}:${code.trim()}`;
  return crypto.createHash("sha256").update(payload).digest("hex");
}

// --- Routes ---

// Health Check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "K.C.C.R (Kai Ctrl Code Reviewer API)",
    version: "1.0.0",
    prompt_version: PROMPT_VERSION,
    timestamp: new Date().toISOString(),
  });
});

// Root Greeting
app.get("/", (req, res) => {
  res.send("🚀 K.C.C.R API is live! Send POST requests to /v1/review");
});

// AI Code Review Endpoint
app.post("/v1/review", async (req, res) => {
  const startTime = Date.now();
  const { code, language = "javascript", fail_on_severity = "high" } = req.body;

  if (!code) {
    return res.status(400).json({ error: "Missing required field: code" });
  }

  // 1. Check Composite Cache (SHA-256)
  const cacheKey = computeCacheKey(language, code);
  if (RESPONSE_CACHE.has(cacheKey)) {
    const cachedData = RESPONSE_CACHE.get(cacheKey);
    const latency = Date.now() - startTime;

    console.log(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        service: "K.C.C.R",
        cached: true,
        latency_ms: latency,
        cache_key: cacheKey,
      }),
    );

    return res.json({
      ...cachedData,
      meta: {
        ...cachedData.meta,
        cached: true,
        latency_ms: latency,
      },
    });
  }

  // 2. Call Anthropic API
  try {
    const userMessage = `LANGUAGE: ${language}\nFAIL THRESHOLD: ${fail_on_severity}\n\nCODE TO REVIEW:\n\`\`\`\n${code}\n\`\`\``;

    const response = await anthropic.messages.create({
      model: "claude-3-5-sonnet-5.5",
      max_tokens: 2500,
      system: SYSTEM_PROMPT,
      messages: [{ role: "user", content: userMessage }],
    });

    const rawText = response.content[0].text.trim();

    // Extract JSON using regex
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error("Model response did not contain a valid JSON object.");
    }

    const reviewData = JSON.parse(jsonMatch[0]);
    const latency = Date.now() - startTime;

    const finalResponse = {
      status: "success",
      summary: reviewData.summary,
      findings: reviewData.findings || [],
      meta: {
        cached: false,
        latency_ms: latency,
        model: "claude-3-5-sonnet-5.5",
        prompt_version: PROMPT_VERSION,
        cache_key: cacheKey,
      },
    };

    // 3. Save to Cache & Return
    RESPONSE_CACHE.set(cacheKey, finalResponse);

    console.log(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        service: "K.C.C.R",
        latency_ms: latency,
        cached: false,
        total_issues: reviewData.summary?.total_issues || 0,
        quality_score: reviewData.summary?.quality_score || 0,
      }),
    );

    return res.json(finalResponse);
  } catch (error) {
    console.error("K.C.C.R Processing Error:", error);
    return res.status(500).json({
      error: "Failed to complete code review audit.",
      details: error.message,
    });
  }
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`🚀 K.C.C.R API running on http://localhost:${PORT}`);
});
