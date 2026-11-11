"use strict";

const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");
const { promisify } = require("node:util");

const HOST = "127.0.0.1";
const PORT = Number(process.env.PORT) || 4173;
const ROOT = __dirname;
const BANKS_DIR = path.join(ROOT, "question-banks");
const SESSIONS_DIR = path.join(ROOT, "session-data");
const DATA_DIR = path.join(ROOT, "data");
const CREDENTIALS_FILE = path.join(DATA_DIR, "user-credentials.json");
const pendingWrites = new Map();
const scrypt = promisify(crypto.scrypt);
let credentialQueue = Promise.resolve();
const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8"
};

function sendJson(response, status, value) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(JSON.stringify(value));
}

function requireLocalOrigin(request, response) {
  const origin = request.headers.origin;
  if (origin && origin !== `http://${HOST}:${PORT}` && origin !== `http://localhost:${PORT}`) {
    sendJson(response, 403, { error: "Requests must come from the local quiz app." });
    return false;
  }
  return true;
}

function withCredentialLock(operation) {
  const result = credentialQueue.then(operation, operation);
  credentialQueue = result.then(() => undefined, () => undefined);
  return result;
}

function validateCredentialsInput(payload) {
  const username = typeof payload?.username === "string" ? payload.username.trim() : "";
  const password = typeof payload?.password === "string" ? payload.password : "";
  if (username.length < 3 || username.length > 32 || /[\u0000-\u001f\u007f]/.test(username)) {
    throw Object.assign(new Error("Username must be 3–32 characters."), { statusCode: 400 });
  }
  if (password.length < 8 || password.length > 128) {
    throw Object.assign(new Error("Password must be 8–128 characters."), { statusCode: 400 });
  }
  return { username, password };
}

async function loadCredentials() {
  try {
    const saved = JSON.parse(await fs.readFile(CREDENTIALS_FILE, "utf8"));
    if (!saved || !Array.isArray(saved.users)) {
      throw new Error("The user credential file has an unexpected format.");
    }
    return saved;
  } catch (error) {
    if (error.code === "ENOENT") return { schemaVersion: "1.0.0", users: [] };
    throw error;
  }
}

async function saveCredentials(credentials) {
  await fs.mkdir(DATA_DIR, { recursive: true });
  const temporaryPath = `${CREDENTIALS_FILE}.${process.pid}.tmp`;
  await fs.writeFile(temporaryPath, JSON.stringify(credentials, null, 2), "utf8");
  await fs.rename(temporaryPath, CREDENTIALS_FILE);
}

async function authenticateUser(action, payload) {
  return withCredentialLock(async () => {
    const { username, password } = validateCredentialsInput(payload);
    const credentials = await loadCredentials();
    const existing = credentials.users.find(user =>
      typeof user.username === "string" && user.username.toLowerCase() === username.toLowerCase()
    );

    if (action === "register") {
      if (existing) {
        throw Object.assign(new Error("That username already exists."), { statusCode: 409 });
      }
      const salt = crypto.randomBytes(16).toString("hex");
      const passwordHash = (await scrypt(password, salt, 64)).toString("hex");
      const user = {
        id: crypto.randomUUID(),
        username,
        passwordAlgorithm: "scrypt",
        salt,
        passwordHash,
        createdAt: new Date().toISOString()
      };
      credentials.users.push(user);
      await saveCredentials(credentials);
      return { id: user.id, username: user.username };
    }

    if (!existing || existing.passwordAlgorithm !== "scrypt" ||
        typeof existing.salt !== "string" || typeof existing.passwordHash !== "string") {
      throw Object.assign(new Error("Username or password is incorrect."), { statusCode: 401 });
    }
    const actualHash = await scrypt(password, existing.salt, 64);
    const expectedHash = Buffer.from(existing.passwordHash, "hex");
    if (expectedHash.length !== actualHash.length || !crypto.timingSafeEqual(actualHash, expectedHash)) {
      throw Object.assign(new Error("Username or password is incorrect."), { statusCode: 401 });
    }
    return { id: existing.id, username: existing.username };
  });
}

async function readRequestBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1024 * 1024) {
      const error = new Error("Request body exceeds the 1 MB limit.");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("Request body must contain valid JSON.");
    error.statusCode = 400;
    throw error;
  }
}

function validateAttempt(payload, bankFiles) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw Object.assign(new Error("Request must be a JSON object."), { statusCode: 400 });
  }
  if (typeof payload.topicFileName !== "string" || !bankFiles.has(payload.topicFileName)) {
    throw Object.assign(new Error("Topic question-bank filename is not recognized."), { statusCode: 400 });
  }
  const attempt = payload.attempt;
  if (!attempt || typeof attempt !== "object" || Array.isArray(attempt) ||
      typeof attempt.id !== "string" || !attempt.id.trim() || attempt.id.length > 128 ||
      typeof attempt.username !== "string" || !attempt.username.trim() || attempt.username.length > 32 ||
      typeof attempt.topicTitle !== "string" || !attempt.topicTitle.trim() || attempt.topicTitle.length > 200 ||
      !Number.isInteger(attempt.total) || attempt.total < 1 || attempt.total > 100 ||
      !Array.isArray(attempt.answers) || attempt.answers.length !== attempt.total ||
      !Array.isArray(attempt.questions) || attempt.questions.length !== attempt.total ||
      !Number.isFinite(attempt.completedAt) || !Number.isFinite(attempt.score)) {
    throw Object.assign(new Error("Session attempt is incomplete or invalid."), { statusCode: 400 });
  }
  return attempt;
}

async function writeAttemptFile(topicFileName, attempt) {
  const topicBaseName = path.basename(topicFileName, path.extname(topicFileName));
  const outputName = `${topicBaseName}-sessions.json`;
  const outputPath = path.join(SESSIONS_DIR, outputName);
  let data = {
    schemaVersion: "1.0.0",
    topicFileName,
    topicTitle: attempt.topicTitle,
    updatedAt: new Date().toISOString(),
    attempts: []
  };

  try {
    const saved = JSON.parse(await fs.readFile(outputPath, "utf8"));
    if (!saved || !Array.isArray(saved.attempts)) {
      throw new Error(`Saved session file has an unexpected format: ${outputName}`);
    }
    data = saved;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const existingIndex = data.attempts.findIndex(item => item && item.id === attempt.id);
  if (existingIndex < 0) data.attempts.push(attempt);
  else data.attempts[existingIndex] = attempt;
  data.topicFileName = topicFileName;
  data.topicTitle = attempt.topicTitle;
  data.updatedAt = new Date().toISOString();

  await fs.mkdir(SESSIONS_DIR, { recursive: true });
  const temporaryPath = `${outputPath}.${process.pid}.tmp`;
  await fs.writeFile(temporaryPath, JSON.stringify(data, null, 2), "utf8");
  await fs.rename(temporaryPath, outputPath);
  return outputName;
}

async function saveAttempt(topicFileName, attempt) {
  const topicBaseName = path.basename(topicFileName, path.extname(topicFileName));
  const outputPath = path.join(SESSIONS_DIR, `${topicBaseName}-sessions.json`);
  const previous = pendingWrites.get(outputPath) || Promise.resolve();
  const write = previous.catch(() => {}).then(() => writeAttemptFile(topicFileName, attempt));
  pendingWrites.set(outputPath, write);
  try {
    return await write;
  } finally {
    if (pendingWrites.get(outputPath) === write) pendingWrites.delete(outputPath);
  }
}

async function handleRequest(request, response) {
  const requestUrl = new URL(request.url, `http://${request.headers.host || `${HOST}:${PORT}`}`);
  if ((requestUrl.pathname === "/api/users/register" || requestUrl.pathname === "/api/users/login") &&
      request.method === "POST") {
    if (!requireLocalOrigin(request, response)) return;
    const action = requestUrl.pathname.endsWith("/register") ? "register" : "login";
    const user = await authenticateUser(action, await readRequestBody(request));
    return sendJson(response, action === "register" ? 201 : 200, { user });
  }

  if (requestUrl.pathname === "/api/question-banks" && request.method === "GET") {
    const entries = await fs.readdir(BANKS_DIR, { withFileTypes: true });
    const banks = [];
    for (const entry of entries.filter(item => item.isFile() && item.name.toLowerCase().endsWith(".json"))) {
      const bank = JSON.parse(await fs.readFile(path.join(BANKS_DIR, entry.name), "utf8"));
      banks.push({ fileName: entry.name, bank });
    }
    banks.sort((left, right) => left.fileName.localeCompare(right.fileName));
    return sendJson(response, 200, { banks });
  }

  if (requestUrl.pathname === "/api/session-attempts" && request.method === "POST") {
    if (!requireLocalOrigin(request, response)) return;
    const payload = await readRequestBody(request);
    const bankFiles = new Set(
      (await fs.readdir(BANKS_DIR, { withFileTypes: true }))
        .filter(item => item.isFile() && item.name.toLowerCase().endsWith(".json"))
        .map(item => item.name)
    );
    const attempt = validateAttempt(payload, bankFiles);
    const fileName = await saveAttempt(payload.topicFileName, attempt);
    return sendJson(response, 200, { saved: true, fileName });
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return sendJson(response, 405, { error: "Method not allowed." });
  }
  let requestPath;
  try {
    requestPath = decodeURIComponent(requestUrl.pathname);
  } catch {
    return sendJson(response, 400, { error: "Invalid URL path." });
  }
  const relativePath = requestPath === "/" ? "index.html" : requestPath.slice(1);
  if (["session-data", "data"].includes(relativePath.split("/")[0])) {
    return sendJson(response, 403, { error: "Local user and session data are not directly served." });
  }
  const filePath = path.resolve(ROOT, relativePath);
  if (filePath !== ROOT && !filePath.startsWith(ROOT + path.sep)) {
    return sendJson(response, 403, { error: "Forbidden." });
  }
  try {
    const body = await fs.readFile(filePath);
    response.writeHead(200, {
      "Content-Type": contentTypes[path.extname(filePath).toLowerCase()] || "application/octet-stream",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    });
    response.end(request.method === "HEAD" ? undefined : body);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "EISDIR") {
      return sendJson(response, 404, { error: "Not found." });
    }
    throw error;
  }
}

const server = http.createServer((request, response) => {
  handleRequest(request, response).catch(error => {
    console.error("Request failed:", error);
    if (!response.headersSent) {
      sendJson(response, error.statusCode || 500, {
        error: error.statusCode ? error.message : "The local server could not complete the request."
      });
    } else {
      response.destroy(error);
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Fieldnotes is running at http://${HOST}:${PORT}`);
  console.log("Press Ctrl+C to stop the local server.");
});
