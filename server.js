"use strict";

const http = require("http");

const PORT = process.env.PORT || 3000;

// ユーザーデータ(メモリ上に保持)
// user_id -> { user_id, password, nickname, comment }
const users = new Map();

// テスト用の初期アカウント
users.set("TaroYamada", {
  user_id: "TaroYamada",
  password: "PaSSwd4TY",
  nickname: "たろー",
  comment: "僕は元気です",
});

// ---------- ユーティリティ ----------

function sendJson(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json),
  });
  res.end(json);
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      if (!data) return resolve({});
      try {
        const parsed = JSON.parse(data);
        resolve(parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {});
      } catch (e) {
        resolve({});
      }
    });
    req.on("error", () => resolve({}));
  });
}

// 文字数(サロゲートペアも1文字として数える)
function charLength(str) {
  return [...str].length;
}

const USER_ID_PATTERN = /^[A-Za-z0-9]+$/;
const PASSWORD_PATTERN = /^[\x21-\x7E]+$/; // 空白と制御コードを除くASCII
const CONTROL_CHAR_PATTERN = /[\x00-\x1F\x7F]/;

// Authorization ヘッダーを検証し、認証できたユーザーを返す(失敗時は null)
function authenticate(req) {
  const header = req.headers["authorization"];
  if (!header || typeof header !== "string") return null;
  const match = header.match(/^Basic\s+(.+)$/i);
  if (!match) return null;

  let decoded;
  try {
    decoded = Buffer.from(match[1].trim(), "base64").toString("utf8");
  } catch (e) {
    return null;
  }
  const sep = decoded.indexOf(":");
  if (sep < 0) return null;

  const userId = decoded.slice(0, sep);
  const password = decoded.slice(sep + 1);
  const user = users.get(userId);
  if (!user || user.password !== password) return null;
  return user;
}

// レスポンス用のユーザー表現
function publicUser(user) {
  const result = {
    user_id: user.user_id,
    nickname: user.nickname ? user.nickname : user.user_id,
  };
  if (user.comment) result.comment = user.comment;
  return result;
}

// ---------- 各エンドポイント ----------

async function handleSignup(req, res) {
  const body = await readBody(req);
  const { user_id, password } = body;

  const fail = (cause) =>
    sendJson(res, 400, { message: "Account creation failed", cause });

  if (
    user_id === undefined || user_id === null || user_id === "" ||
    password === undefined || password === null || password === ""
  ) {
    return fail("Required user_id and password");
  }
  if (typeof user_id !== "string" || typeof password !== "string") {
    return fail("Incorrect character pattern");
  }
  if (
    user_id.length < 6 || user_id.length > 20 ||
    password.length < 8 || password.length > 20
  ) {
    return fail("Input length is incorrect");
  }
  if (!USER_ID_PATTERN.test(user_id) || !PASSWORD_PATTERN.test(password)) {
    return fail("Incorrect character pattern");
  }
  if (users.has(user_id)) {
    return fail("Already same user_id is used");
  }

  const user = { user_id, password, nickname: "", comment: "" };
  users.set(user_id, user);

  return sendJson(res, 200, {
    message: "Account successfully created",
    user: { user_id, nickname: user_id },
  });
}

function handleGetUser(req, res, targetId) {
  const authUser = authenticate(req);
  if (!authUser) {
    return sendJson(res, 401, { message: "Authentication failed" });
  }
  const target = users.get(targetId);
  if (!target) {
    return sendJson(res, 404, { message: "No user found" });
  }
  return sendJson(res, 200, {
    message: "User details by user_id",
    user: publicUser(target),
  });
}

async function handlePatchUser(req, res, targetId) {
  const authUser = authenticate(req);
  if (!authUser) {
    return sendJson(res, 401, { message: "Authentication failed" });
  }
  const target = users.get(targetId);
  if (!target) {
    return sendJson(res, 404, { message: "No user found" });
  }
  if (authUser.user_id !== targetId) {
    return sendJson(res, 403, { message: "No permission for update" });
  }

  const body = await readBody(req);
  const fail = (cause) =>
    sendJson(res, 400, { message: "User updation failed", cause });

  if ("user_id" in body || "password" in body) {
    return fail("Not updatable user_id and password");
  }

  const hasNickname = body.nickname !== undefined && body.nickname !== null;
  const hasComment = body.comment !== undefined && body.comment !== null;
  if (!hasNickname && !hasComment) {
    return fail("Required nickname or comment");
  }

  const invalid = (value, max) =>
    typeof value !== "string" ||
    charLength(value) > max ||
    CONTROL_CHAR_PATTERN.test(value);

  if ((hasNickname && invalid(body.nickname, 30)) || (hasComment && invalid(body.comment, 100))) {
    return fail("String length limit exceeded or containing invalid characters");
  }

  // 空文字の nickname は初期値(user_id)に戻す、空文字の comment はクリア
  if (hasNickname) target.nickname = body.nickname;
  if (hasComment) target.comment = body.comment;

  return sendJson(res, 200, {
    message: "User successfully updated",
    user: publicUser(target),
  });
}

function handleClose(req, res) {
  const authUser = authenticate(req);
  if (!authUser) {
    return sendJson(res, 401, { message: "Authentication failed" });
  }
  users.delete(authUser.user_id);
  return sendJson(res, 200, { message: "Account and user successfully removed" });
}

// ---------- ルーティング ----------

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = req.method.toUpperCase();

    if (path === "/signup") {
      if (method === "POST") return await handleSignup(req, res);
      return sendJson(res, 405, { message: "Method not allowed" });
    }

    if (path === "/close") {
      if (method === "POST") return handleClose(req, res);
      return sendJson(res, 405, { message: "Method not allowed" });
    }

    const userMatch = path.match(/^\/users\/([^/]+)$/);
    if (userMatch) {
      const targetId = decodeURIComponent(userMatch[1]);
      if (method === "GET") return handleGetUser(req, res, targetId);
      if (method === "PATCH") return await handlePatchUser(req, res, targetId);
      return sendJson(res, 405, { message: "Method not allowed" });
    }

    return sendJson(res, 404, { message: "Not found" });
  } catch (e) {
    return sendJson(res, 500, { message: "Internal server error" });
  }
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
