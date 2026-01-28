import crypto from "node:crypto";
import { XMLParser, XMLBuilder } from "fast-xml-parser";
import { normalizePluginHttpPath } from "clawdbot/plugin-sdk";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, unlink, mkdir, appendFile } from "node:fs/promises";
import { existsSync, appendFileSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, dirname } from "node:path";
import { randomUUID } from "node:crypto";

const execFileAsync = promisify(execFile);
const xmlParser = new XMLParser({
  ignoreAttributes: false,
  trimValues: true,
  processEntities: false, // 禁用实体处理，防止 XXE 攻击
});
const xmlBuilder = new XMLBuilder({ ignoreAttributes: false });

// 请求体大小限制 (1MB)
const MAX_REQUEST_BODY_SIZE = 1024 * 1024;

function readRequestBody(req, maxSize = MAX_REQUEST_BODY_SIZE) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;

    req.on("data", (c) => {
      const chunk = Buffer.isBuffer(c) ? c : Buffer.from(c);
      totalSize += chunk.length;
      if (totalSize > maxSize) {
        reject(new Error(`Request body too large (limit: ${maxSize} bytes)`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sha1(text) {
  return crypto.createHash("sha1").update(text).digest("hex");
}

function computeMsgSignature({ token, timestamp, nonce, encrypt }) {
  const arr = [token, timestamp, nonce, encrypt].map(String).sort();
  return sha1(arr.join(""));
}

function decodeAesKey(aesKey) {
  const base64 = aesKey.endsWith("=") ? aesKey : `${aesKey}=`;
  return Buffer.from(base64, "base64");
}

function pkcs7Unpad(buf) {
  const pad = buf[buf.length - 1];
  if (pad < 1 || pad > 32) return buf;
  return buf.subarray(0, buf.length - pad);
}

function decryptWecom({ aesKey, cipherTextBase64 }) {
  const key = decodeAesKey(aesKey);
  const iv = key.subarray(0, 16);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  decipher.setAutoPadding(false);
  const plain = Buffer.concat([
    decipher.update(Buffer.from(cipherTextBase64, "base64")),
    decipher.final(),
  ]);
  const unpadded = pkcs7Unpad(plain);

  const msgLen = unpadded.readUInt32BE(16);
  const msgStart = 20;
  const msgEnd = msgStart + msgLen;
  const msg = unpadded.subarray(msgStart, msgEnd).toString("utf8");
  const corpId = unpadded.subarray(msgEnd).toString("utf8");
  return { msg, corpId };
}

function parseIncomingXml(xml) {
  const obj = xmlParser.parse(xml);
  const root = obj?.xml ?? obj;
  return root;
}

function requireEnv(name, fallback) {
  const v = process.env[name];
  if (v == null || v === "") return fallback;
  return v;
}

function asNumber(v, fallback = null) {
  if (v == null) return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

// 企业微信 access_token 缓存（支持多账户）
const accessTokenCaches = new Map(); // key: corpId, value: { token, expiresAt, refreshPromise }

async function getWecomAccessToken({ corpId, corpSecret }) {
  const cacheKey = corpId;
  let cache = accessTokenCaches.get(cacheKey);

  if (!cache) {
    cache = { token: null, expiresAt: 0, refreshPromise: null };
    accessTokenCaches.set(cacheKey, cache);
  }

  const now = Date.now();
  if (cache.token && cache.expiresAt > now + 60000) {
    return cache.token;
  }

  // 如果已有刷新在进行中，等待它完成
  if (cache.refreshPromise) {
    return cache.refreshPromise;
  }

  cache.refreshPromise = (async () => {
    try {
      const tokenUrl = `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${encodeURIComponent(corpId)}&corpsecret=${encodeURIComponent(corpSecret)}`;
      const tokenRes = await fetch(tokenUrl);
      const tokenJson = await tokenRes.json();
      if (!tokenJson?.access_token) {
        throw new Error(`WeCom gettoken failed: ${JSON.stringify(tokenJson)}`);
      }

      cache.token = tokenJson.access_token;
      cache.expiresAt = Date.now() + (tokenJson.expires_in || 7200) * 1000;

      return cache.token;
    } finally {
      cache.refreshPromise = null;
    }
  })();

  return cache.refreshPromise;
}

// Markdown 转换为企业微信纯文本
// 企业微信不支持 Markdown 渲染，需要转换为可读的纯文本格式
function markdownToWecomText(markdown) {
  if (!markdown) return markdown;

  let text = markdown;

  // 移除代码块标记，保留内容并添加缩进
  text = text.replace(/```(\w*)\n([\s\S]*?)```/g, (match, lang, code) => {
    const lines = code.trim().split('\n').map(line => '  ' + line).join('\n');
    return lang ? `[${lang}]\n${lines}` : lines;
  });

  // 移除行内代码标记
  text = text.replace(/`([^`]+)`/g, '$1');

  // 转换标题为带符号的格式
  text = text.replace(/^### (.+)$/gm, '▸ $1');
  text = text.replace(/^## (.+)$/gm, '■ $1');
  text = text.replace(/^# (.+)$/gm, '◆ $1');

  // 移除粗体/斜体标记，保留内容
  text = text.replace(/\*\*\*([^*]+)\*\*\*/g, '$1');
  text = text.replace(/\*\*([^*]+)\*\*/g, '$1');
  text = text.replace(/\*([^*]+)\*/g, '$1');
  text = text.replace(/___([^_]+)___/g, '$1');
  text = text.replace(/__([^_]+)__/g, '$1');
  text = text.replace(/_([^_]+)_/g, '$1');

  // 转换链接为 "文字 (URL)" 格式
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)');

  // 转换无序列表标记
  text = text.replace(/^[\*\-] /gm, '• ');

  // 转换有序列表（保持原样，数字已经可读）

  // 转换水平线
  text = text.replace(/^[-*_]{3,}$/gm, '────────────');

  // 移除图片标记，保留 alt 文字
  text = text.replace(/!\[([^\]]*)\]\([^)]+\)/g, '[图片: $1]');

  // 清理多余空行（保留最多两个连续换行）
  text = text.replace(/\n{3,}/g, '\n\n');

  return text.trim();
}

// 企业微信文本消息限制 (2048 字节，中文约 680 字)
const WECOM_TEXT_BYTE_LIMIT = 2000; // 留点余量

// 计算字符串的 UTF-8 字节长度
function getByteLength(str) {
  return Buffer.byteLength(str, 'utf8');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// 简单的限流器，防止触发企业微信 API 限流
class RateLimiter {
  constructor({ maxConcurrent = 3, minInterval = 200 }) {
    this.maxConcurrent = maxConcurrent;
    this.minInterval = minInterval;
    this.running = 0;
    this.queue = [];
    this.lastExecution = 0;
  }

  async execute(fn) {
    return new Promise((resolve, reject) => {
      this.queue.push({ fn, resolve, reject });
      this.processQueue();
    });
  }

  async processQueue() {
    if (this.running >= this.maxConcurrent || this.queue.length === 0) {
      return;
    }

    const now = Date.now();
    const waitTime = Math.max(0, this.lastExecution + this.minInterval - now);

    if (waitTime > 0) {
      setTimeout(() => this.processQueue(), waitTime);
      return;
    }

    this.running++;
    this.lastExecution = Date.now();

    const { fn, resolve, reject } = this.queue.shift();

    try {
      const result = await fn();
      resolve(result);
    } catch (err) {
      reject(err);
    } finally {
      this.running--;
      this.processQueue();
    }
  }
}

// API 调用限流器（最多3并发，200ms间隔）
const apiLimiter = new RateLimiter({ maxConcurrent: 3, minInterval: 200 });

// 消息处理限流器（最多5并发）
const messageProcessLimiter = new RateLimiter({ maxConcurrent: 5, minInterval: 0 });

// 消息分段函数，按字节限制分割（企业微信限制 2048 字节）
function splitWecomText(text, byteLimit = WECOM_TEXT_BYTE_LIMIT) {
  if (getByteLength(text) <= byteLimit) return [text];

  const chunks = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (getByteLength(remaining) <= byteLimit) {
      chunks.push(remaining);
      break;
    }

    // 二分查找合适的分割点（按字节）
    let low = 1;
    let high = remaining.length;

    while (low < high) {
      const mid = Math.floor((low + high + 1) / 2);
      if (getByteLength(remaining.slice(0, mid)) <= byteLimit) {
        low = mid;
      } else {
        high = mid - 1;
      }
    }
    let splitIndex = low;

    // 尝试在自然断点处分割（往前找 200 字符范围内）
    const searchStart = Math.max(0, splitIndex - 200);
    const searchText = remaining.slice(searchStart, splitIndex);

    // 优先在段落处分割
    let naturalBreak = searchText.lastIndexOf("\n\n");
    if (naturalBreak === -1) {
      // 其次在换行处
      naturalBreak = searchText.lastIndexOf("\n");
    }
    if (naturalBreak === -1) {
      // 再次在句号处
      naturalBreak = searchText.lastIndexOf("。");
      if (naturalBreak !== -1) naturalBreak += 1; // 包含句号
    }
    if (naturalBreak !== -1 && naturalBreak > 0) {
      splitIndex = searchStart + naturalBreak;
    }

    // 确保至少分割一些内容
    if (splitIndex <= 0) {
      splitIndex = Math.min(remaining.length, Math.floor(byteLimit / 3));
    }

    chunks.push(remaining.slice(0, splitIndex).trim());
    remaining = remaining.slice(splitIndex).trim();
  }

  return chunks.filter(c => c.length > 0);
}

// 发送单条文本消息（内部函数，带限流）
async function sendWecomTextSingle({ corpId, corpSecret, agentId, toUser, text }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({ corpId, corpSecret });

    const sendUrl = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;
    const body = {
      touser: toUser,
      msgtype: "text",
      agentid: agentId,
      text: { content: text },
      safe: 0,
    };
    const sendRes = await fetch(sendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const sendJson = await sendRes.json();
    if (sendJson?.errcode !== 0) {
      throw new Error(`WeCom message/send failed: ${JSON.stringify(sendJson)}`);
    }
    return sendJson;
  });
}

// 发送文本消息（支持自动分段）
async function sendWecomText({ corpId, corpSecret, agentId, toUser, text, logger }) {
  const chunks = splitWecomText(text);

  logger?.info?.(`wecom: splitting message into ${chunks.length} chunks, total bytes=${getByteLength(text)}`);

  for (let i = 0; i < chunks.length; i++) {
    logger?.info?.(`wecom: sending chunk ${i + 1}/${chunks.length}, bytes=${getByteLength(chunks[i])}`);
    await sendWecomTextSingle({ corpId, corpSecret, agentId, toUser, text: chunks[i] });
    // 分段发送时添加间隔，避免触发限流
    if (i < chunks.length - 1) {
      await sleep(300);
    }
  }
}

// 上传临时素材到企业微信
async function uploadWecomMedia({ corpId, corpSecret, type, buffer, filename }) {
  const accessToken = await getWecomAccessToken({ corpId, corpSecret });
  const uploadUrl = `https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token=${encodeURIComponent(accessToken)}&type=${encodeURIComponent(type)}`;

  // 构建 multipart/form-data
  const boundary = "----WecomMediaUpload" + Date.now();
  const header = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="media"; filename="${filename}"\r\n` +
    `Content-Type: application/octet-stream\r\n\r\n`
  );
  const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body = Buffer.concat([header, buffer, footer]);

  const res = await fetch(uploadUrl, {
    method: "POST",
    headers: {
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
    },
    body,
  });

  const json = await res.json();
  if (json.errcode !== 0) {
    throw new Error(`WeCom media upload failed: ${JSON.stringify(json)}`);
  }

  return json.media_id;
}

// 发送图片消息（带限流）
async function sendWecomImage({ corpId, corpSecret, agentId, toUser, mediaId }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({ corpId, corpSecret });
    const sendUrl = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;

    const body = {
      touser: toUser,
      msgtype: "image",
      agentid: agentId,
      image: { media_id: mediaId },
      safe: 0,
    };

    const sendRes = await fetch(sendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const sendJson = await sendRes.json();
    if (sendJson?.errcode !== 0) {
      throw new Error(`WeCom image send failed: ${JSON.stringify(sendJson)}`);
    }
    return sendJson;
  });
}

// 发送视频消息（带限流）
async function sendWecomVideo({ corpId, corpSecret, agentId, toUser, mediaId, title, description }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({ corpId, corpSecret });
    const sendUrl = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;
    const body = {
      touser: toUser,
      msgtype: "video",
      agentid: agentId,
      video: {
        media_id: mediaId,
        ...(title ? { title } : {}),
        ...(description ? { description } : {}),
      },
      safe: 0,
    };
    const sendRes = await fetch(sendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const sendJson = await sendRes.json();
    if (sendJson?.errcode !== 0) {
      throw new Error(`WeCom video send failed: ${JSON.stringify(sendJson)}`);
    }
    return sendJson;
  });
}

// 发送文件消息（带限流）
async function sendWecomFile({ corpId, corpSecret, agentId, toUser, mediaId }) {
  return apiLimiter.execute(async () => {
    const accessToken = await getWecomAccessToken({ corpId, corpSecret });
    const sendUrl = `https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token=${encodeURIComponent(accessToken)}`;
    const body = {
      touser: toUser,
      msgtype: "file",
      agentid: agentId,
      file: { media_id: mediaId },
      safe: 0,
    };
    const sendRes = await fetch(sendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const sendJson = await sendRes.json();
    if (sendJson?.errcode !== 0) {
      throw new Error(`WeCom file send failed: ${JSON.stringify(sendJson)}`);
    }
    return sendJson;
  });
}

// 从 URL 下载媒体文件
async function fetchMediaFromUrl(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch media from URL: ${res.status}`);
  }
  const buffer = Buffer.from(await res.arrayBuffer());
  const contentType = res.headers.get("content-type") || "application/octet-stream";
  return { buffer, contentType };
}

const WecomChannelPlugin = {
  id: "wecom",
  meta: {
    id: "wecom",
    label: "WeCom",
    selectionLabel: "WeCom (企业微信自建应用)",
    docsPath: "/channels/wecom",
    blurb: "Enterprise WeChat internal app via callback + send API.",
    aliases: ["wework", "qiwei", "wxwork"],
  },
  capabilities: {
    chatTypes: ["direct", "group"],
    media: {
      inbound: true,
      outbound: true, // 阶段二完成：支持发送图片
    },
    markdown: true, // 阶段三完成：支持 Markdown 转换
  },
  config: {
    listAccountIds: (cfg) => Object.keys(cfg.channels?.wecom?.accounts ?? {}),
    resolveAccount: (cfg, accountId) =>
      (cfg.channels?.wecom?.accounts?.[accountId ?? "default"] ?? { accountId }),
  },
  outbound: {
    deliveryMode: "direct",
    resolveTarget: ({ to }) => {
      const trimmed = to?.trim();
      if (!trimmed) return { ok: false, error: new Error("WeCom requires --to <UserId>") };
      return { ok: true, to: trimmed };
    },
    sendText: async ({ to, text }) => {
      const config = getWecomConfig();
      if (!config?.corpId || !config?.corpSecret || !config?.agentId) {
        return { ok: false, error: new Error("WeCom not configured (check channels.wecom in clawdbot.json)") };
      }
      await sendWecomText({ corpId: config.corpId, corpSecret: config.corpSecret, agentId: config.agentId, toUser: to, text });
      return { ok: true, provider: "wecom" };
    },
  },
  // 入站消息处理 - clawdbot 会调用这个方法
  inbound: {
    // 当消息需要回复时，clawdbot 会调用这个方法
    deliverReply: async ({ to, text, accountId, mediaUrl, mediaType }) => {
      const config = getWecomConfig();
      if (!config?.corpId || !config?.corpSecret || !config?.agentId) {
        throw new Error("WeCom not configured (check channels.wecom in clawdbot.json)");
      }
      const { corpId, corpSecret, agentId } = config;
      // to 格式为 "wecom:userid"，需要提取 userid
      const userId = to.startsWith("wecom:") ? to.slice(6) : to;

      // 如果有媒体附件，先发送媒体
      if (mediaUrl && mediaType === "image") {
        try {
          const { buffer } = await fetchMediaFromUrl(mediaUrl);
          const mediaId = await uploadWecomMedia({
            corpId, corpSecret,
            type: "image",
            buffer,
            filename: "image.jpg",
          });
          await sendWecomImage({ corpId, corpSecret, agentId, toUser: userId, mediaId });
        } catch (mediaErr) {
          // 媒体发送失败不阻止文本发送，只记录警告
          console.warn?.(`wecom: failed to send media: ${mediaErr.message}`);
        }
      }

      // 发送文本消息
      if (text) {
        await sendWecomText({ corpId, corpSecret, agentId, toUser: userId, text });
      }

      return { ok: true };
    },
  },
};

// 存储 runtime 引用以便在消息处理中使用
let gatewayRuntime = null;

// 存储 gateway broadcast 上下文，用于向 Chat UI 广播消息
let gatewayBroadcastCtx = null;

// 写入消息到 session transcript 文件，使 Chat UI 可以显示
async function writeToTranscript({ sessionKey, role, text, logger }) {
  try {
    const stateDir = process.env.CLAWDBOT_STATE_DIR || join(homedir(), ".clawdbot");
    const sessionsDir = join(stateDir, "agents", "main", "sessions");
    const sessionsJsonPath = join(sessionsDir, "sessions.json");

    // 读取 sessions.json 获取 sessionId
    if (!existsSync(sessionsJsonPath)) {
      logger?.warn?.("wecom: sessions.json not found");
      return;
    }

    const { readFileSync } = await import("node:fs");
    const sessionsData = JSON.parse(readFileSync(sessionsJsonPath, "utf8"));
    const sessionEntry = sessionsData[sessionKey] || sessionsData[sessionKey.toLowerCase()];

    if (!sessionEntry?.sessionId) {
      logger?.warn?.(`wecom: session entry not found for ${sessionKey}`);
      return;
    }

    const transcriptPath = sessionEntry.sessionFile || join(sessionsDir, `${sessionEntry.sessionId}.jsonl`);

    const now = Date.now();
    const messageId = randomUUID().slice(0, 8);

    const transcriptEntry = {
      type: "message",
      id: messageId,
      timestamp: new Date(now).toISOString(),
      message: {
        role,
        content: [{ type: "text", text }],
        timestamp: now,
        stopReason: role === "assistant" ? "end_turn" : undefined,
        usage: role === "assistant" ? { input: 0, output: 0, totalTokens: 0 } : undefined,
      },
    };

    appendFileSync(transcriptPath, `${JSON.stringify(transcriptEntry)}\n`, "utf-8");
    logger?.info?.(`wecom: wrote ${role} message to transcript`);
  } catch (err) {
    logger?.warn?.(`wecom: failed to write transcript: ${err.message}`);
  }
}

// 广播消息到 Chat UI
function broadcastToChatUI({ sessionKey, role, text, runId, state }) {
  if (!gatewayBroadcastCtx) {
    return; // 没有 broadcast 上下文，跳过
  }

  try {
    const chatPayload = {
      runId: runId || `wecom-${Date.now()}`,
      sessionKey,
      seq: 0,
      state: state || "final",
      message: {
        role: role || "user",
        content: [{ type: "text", text: text || "" }],
        timestamp: Date.now(),
      },
    };

    gatewayBroadcastCtx.broadcast("chat", chatPayload);
    gatewayBroadcastCtx.bridgeSendToSession(sessionKey, "chat", chatPayload);
  } catch (err) {
    // 忽略广播错误，不影响主流程
  }
}

// 多账户配置存储
const wecomAccounts = new Map(); // key: accountId, value: config
let defaultAccountId = "default";

// 获取 wecom 配置（支持多账户）
// 优先级: channels.wecom > env.vars > 进程环境变量
function getWecomConfig(api, accountId = null) {
  const targetAccountId = accountId || defaultAccountId;

  // 如果已缓存，直接返回
  if (wecomAccounts.has(targetAccountId)) {
    return wecomAccounts.get(targetAccountId);
  }

  const cfg = api?.config ?? gatewayRuntime?.config;

  // 1. 优先从 channels.wecom 读取配置
  const channelConfig = cfg?.channels?.wecom;
  if (channelConfig && targetAccountId === "default") {
    const corpId = channelConfig.corpId;
    const corpSecret = channelConfig.corpSecret;
    const agentId = channelConfig.agentId;
    const callbackToken = channelConfig.callbackToken;
    const callbackAesKey = channelConfig.callbackAesKey;
    const webhookPath = channelConfig.webhookPath || "/wecom/callback";

    if (corpId && corpSecret && agentId) {
      const config = {
        accountId: targetAccountId,
        corpId,
        corpSecret,
        agentId: asNumber(agentId),
        callbackToken,
        callbackAesKey,
        webhookPath,
        enabled: channelConfig.enabled !== false,
      };
      wecomAccounts.set(targetAccountId, config);
      return config;
    }
  }

  // 2. 多账户支持：从 channels.wecom.accounts 读取
  const accountConfig = cfg?.channels?.wecom?.accounts?.[targetAccountId];
  if (accountConfig) {
    const corpId = accountConfig.corpId;
    const corpSecret = accountConfig.corpSecret;
    const agentId = accountConfig.agentId;
    const callbackToken = accountConfig.callbackToken;
    const callbackAesKey = accountConfig.callbackAesKey;
    const webhookPath = accountConfig.webhookPath || "/wecom/callback";

    if (corpId && corpSecret && agentId) {
      const config = {
        accountId: targetAccountId,
        corpId,
        corpSecret,
        agentId: asNumber(agentId),
        callbackToken,
        callbackAesKey,
        webhookPath,
        enabled: accountConfig.enabled !== false,
      };
      wecomAccounts.set(targetAccountId, config);
      return config;
    }
  }

  // 3. 回退到 env.vars（兼容旧配置）
  const envVars = cfg?.env?.vars ?? {};
  const accountPrefix = targetAccountId === "default" ? "WECOM" : `WECOM_${targetAccountId.toUpperCase()}`;

  let corpId = envVars[`${accountPrefix}_CORP_ID`] || (targetAccountId === "default" ? envVars.WECOM_CORP_ID : null);
  let corpSecret = envVars[`${accountPrefix}_CORP_SECRET`] || (targetAccountId === "default" ? envVars.WECOM_CORP_SECRET : null);
  let agentId = envVars[`${accountPrefix}_AGENT_ID`] || (targetAccountId === "default" ? envVars.WECOM_AGENT_ID : null);
  let callbackToken = envVars[`${accountPrefix}_CALLBACK_TOKEN`] || (targetAccountId === "default" ? envVars.WECOM_CALLBACK_TOKEN : null);
  let callbackAesKey = envVars[`${accountPrefix}_CALLBACK_AES_KEY`] || (targetAccountId === "default" ? envVars.WECOM_CALLBACK_AES_KEY : null);
  let webhookPath = envVars[`${accountPrefix}_WEBHOOK_PATH`] || (targetAccountId === "default" ? envVars.WECOM_WEBHOOK_PATH : null) || "/wecom/callback";

  // 4. 最后回退到进程环境变量
  if (!corpId) corpId = requireEnv(`${accountPrefix}_CORP_ID`) || requireEnv("WECOM_CORP_ID");
  if (!corpSecret) corpSecret = requireEnv(`${accountPrefix}_CORP_SECRET`) || requireEnv("WECOM_CORP_SECRET");
  if (!agentId) agentId = requireEnv(`${accountPrefix}_AGENT_ID`) || requireEnv("WECOM_AGENT_ID");
  if (!callbackToken) callbackToken = requireEnv(`${accountPrefix}_CALLBACK_TOKEN`) || requireEnv("WECOM_CALLBACK_TOKEN");
  if (!callbackAesKey) callbackAesKey = requireEnv(`${accountPrefix}_CALLBACK_AES_KEY`) || requireEnv("WECOM_CALLBACK_AES_KEY");

  if (corpId && corpSecret && agentId) {
    const config = {
      accountId: targetAccountId,
      corpId,
      corpSecret,
      agentId: asNumber(agentId),
      callbackToken,
      callbackAesKey,
      webhookPath,
    };
    wecomAccounts.set(targetAccountId, config);
    return config;
  }

  return null;
}

// 列出所有已配置的账户ID
function listWecomAccountIds(api) {
  const cfg = api?.config ?? gatewayRuntime?.config;
  const accountIds = new Set(["default"]);

  // 1. 从 channels.wecom.accounts 读取
  const channelAccounts = cfg?.channels?.wecom?.accounts;
  if (channelAccounts) {
    for (const accountId of Object.keys(channelAccounts)) {
      accountIds.add(accountId);
    }
  }

  // 2. 从 env.vars 读取 (兼容旧配置)
  const envVars = cfg?.env?.vars ?? {};
  for (const key of Object.keys(envVars)) {
    const match = key.match(/^WECOM_([A-Z0-9]+)_CORP_ID$/);
    if (match && match[1] !== "CORP") {
      accountIds.add(match[1].toLowerCase());
    }
  }

  return Array.from(accountIds);
}

export default function register(api) {
  // 保存 runtime 引用
  gatewayRuntime = api.runtime;

  // 初始化配置
  const cfg = getWecomConfig(api);
  if (cfg) {
    api.logger.info?.(`wecom: config loaded (corpId=${cfg.corpId?.slice(0, 8)}...)`);
  } else {
    api.logger.warn?.("wecom: no configuration found (check channels.wecom in clawdbot.json)");
  }

  api.registerChannel({ plugin: WecomChannelPlugin });

  // 注册一个 gateway 方法来获取 broadcast 上下文
  // 这个方法会在插件加载时被调用，用于捕获 broadcast 上下文
  api.registerGatewayMethod("wecom.init", async (ctx, nodeId, params) => {
    gatewayBroadcastCtx = ctx;
    api.logger.info?.("wecom: gateway broadcast context captured");
    return { ok: true };
  });

  // 注册一个 gateway 方法用于广播消息到 Chat UI
  api.registerGatewayMethod("wecom.broadcast", async (ctx, nodeId, params) => {
    const { sessionKey, runId, message, state } = params || {};
    if (!sessionKey || !message) {
      return { ok: false, error: { message: "missing sessionKey or message" } };
    }

    const chatPayload = {
      runId: runId || `wecom-${Date.now()}`,
      sessionKey,
      seq: 0,
      state: state || "final",
      message: {
        role: message.role || "user",
        content: [{ type: "text", text: message.text || "" }],
        timestamp: Date.now(),
      },
    };

    ctx.broadcast("chat", chatPayload);
    ctx.bridgeSendToSession(sessionKey, "chat", chatPayload);

    // 保存 broadcast 上下文供后续使用
    gatewayBroadcastCtx = ctx;

    return { ok: true };
  });

  const webhookPath = cfg?.webhookPath || "/wecom/callback";
  const normalizedPath = normalizePluginHttpPath(webhookPath, "/wecom/callback") ?? "/wecom/callback";

  api.registerHttpRoute({
    path: normalizedPath,
    handler: async (req, res) => {
      const config = getWecomConfig(api);
      const token = config?.callbackToken;
      const aesKey = config?.callbackAesKey;

      const url = new URL(req.url ?? "/", "http://localhost");
      const msg_signature = url.searchParams.get("msg_signature") ?? "";
      const timestamp = url.searchParams.get("timestamp") ?? "";
      const nonce = url.searchParams.get("nonce") ?? "";
      const echostr = url.searchParams.get("echostr") ?? "";

      // Health check
      if (req.method === "GET" && !echostr) {
        res.statusCode = token && aesKey ? 200 : 500;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end(token && aesKey ? "wecom webhook ok" : "wecom webhook not configured");
        return;
      }

      if (!token || !aesKey) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("WeCom plugin not configured (missing token/aesKey)");
        return;
      }

      if (req.method === "GET") {
        // URL verification
        const expected = computeMsgSignature({ token, timestamp, nonce, encrypt: echostr });
        if (!msg_signature || expected !== msg_signature) {
          res.statusCode = 401;
          res.setHeader("Content-Type", "text/plain; charset=utf-8");
          res.end("Invalid signature");
          return;
        }
        const { msg: plainEchostr } = decryptWecom({ aesKey, cipherTextBase64: echostr });
        res.statusCode = 200;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end(plainEchostr);
        return;
      }

      if (req.method !== "POST") {
        res.statusCode = 405;
        res.setHeader("Allow", "GET, POST");
        res.end();
        return;
      }

      const rawXml = await readRequestBody(req);
      const incoming = parseIncomingXml(rawXml);
      const encrypt = incoming?.Encrypt;
      if (!encrypt) {
        res.statusCode = 400;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("Missing Encrypt");
        return;
      }

      const expected = computeMsgSignature({ token, timestamp, nonce, encrypt });
      if (!msg_signature || expected !== msg_signature) {
        res.statusCode = 401;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("Invalid signature");
        return;
      }

      // ACK quickly (WeCom expects fast response within 5 seconds)
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("success");

      const { msg: decryptedXml } = decryptWecom({ aesKey, cipherTextBase64: encrypt });
      const msgObj = parseIncomingXml(decryptedXml);

      // 检测是否为群聊消息
      // 企业微信群聊消息会有 ChatId 字段（外部群）或通过应用消息接收
      const chatId = msgObj.ChatId || null;
      const isGroupChat = !!chatId;

      api.logger.info?.(
        `wecom inbound: FromUserName=${msgObj?.FromUserName} MsgType=${msgObj?.MsgType} ChatId=${chatId || "N/A"} Content=${(msgObj?.Content ?? "").slice?.(0, 80)}`
      );

      const fromUser = msgObj.FromUserName;
      const msgType = msgObj.MsgType;

      // 异步处理消息，不阻塞响应
      if (msgType === "text" && msgObj?.Content) {
        processInboundMessage({ api, fromUser, content: msgObj.Content, msgType: "text", chatId, isGroupChat }).catch((err) => {
          api.logger.error?.(`wecom: async message processing failed: ${err.message}`);
        });
      } else if (msgType === "image" && msgObj?.MediaId) {
        processInboundMessage({ api, fromUser, mediaId: msgObj.MediaId, msgType: "image", picUrl: msgObj.PicUrl, chatId, isGroupChat }).catch((err) => {
          api.logger.error?.(`wecom: async image processing failed: ${err.message}`);
        });
      } else if (msgType === "voice" && msgObj?.MediaId) {
        // Recognition 字段包含企业微信自动语音识别的结果（需要在企业微信后台开启）
        processInboundMessage({ api, fromUser, mediaId: msgObj.MediaId, msgType: "voice", recognition: msgObj.Recognition, chatId, isGroupChat }).catch((err) => {
          api.logger.error?.(`wecom: async voice processing failed: ${err.message}`);
        });
      } else if (msgType === "video" && msgObj?.MediaId) {
        processInboundMessage({
          api, fromUser,
          mediaId: msgObj.MediaId,
          msgType: "video",
          thumbMediaId: msgObj.ThumbMediaId,
          chatId, isGroupChat
        }).catch((err) => {
          api.logger.error?.(`wecom: async video processing failed: ${err.message}`);
        });
      } else if (msgType === "file" && msgObj?.MediaId) {
        processInboundMessage({
          api, fromUser,
          mediaId: msgObj.MediaId,
          msgType: "file",
          fileName: msgObj.FileName,
          fileSize: msgObj.FileSize,
          chatId, isGroupChat
        }).catch((err) => {
          api.logger.error?.(`wecom: async file processing failed: ${err.message}`);
        });
      } else if (msgType === "link") {
        // 链接分享消息
        processInboundMessage({
          api, fromUser,
          msgType: "link",
          linkTitle: msgObj.Title,
          linkDescription: msgObj.Description,
          linkUrl: msgObj.Url,
          linkPicUrl: msgObj.PicUrl,
          chatId, isGroupChat
        }).catch((err) => {
          api.logger.error?.(`wecom: async link processing failed: ${err.message}`);
        });
      } else {
        api.logger.info?.(`wecom: ignoring unsupported message type=${msgType}`);
      }
    },
  });

  api.logger.info?.(`wecom: registered webhook at ${normalizedPath}`);
}

// 下载企业微信媒体文件
async function downloadWecomMedia({ corpId, corpSecret, mediaId }) {
  const accessToken = await getWecomAccessToken({ corpId, corpSecret });
  const mediaUrl = `https://qyapi.weixin.qq.com/cgi-bin/media/get?access_token=${encodeURIComponent(accessToken)}&media_id=${encodeURIComponent(mediaId)}`;

  const res = await fetch(mediaUrl);
  if (!res.ok) {
    throw new Error(`Failed to download media: ${res.status}`);
  }

  const contentType = res.headers.get("content-type") || "";

  // 如果返回 JSON，说明有错误
  if (contentType.includes("application/json")) {
    const json = await res.json();
    throw new Error(`WeCom media download failed: ${JSON.stringify(json)}`);
  }

  const buffer = await res.arrayBuffer();
  return {
    buffer: Buffer.from(buffer),
    contentType,
  };
}

// 命令处理函数
async function handleHelpCommand({ api, fromUser, corpId, corpSecret, agentId }) {
  const helpText = `🤖 AI 助手使用帮助

可用命令：
/help - 显示此帮助信息
/clear - 清除会话历史，开始新对话
/status - 查看系统状态

直接发送消息即可与 AI 对话。
支持发送图片，AI 会分析图片内容。`;

  await sendWecomText({ corpId, corpSecret, agentId, toUser: fromUser, text: helpText });
  return true;
}

async function handleClearCommand({ api, fromUser, corpId, corpSecret, agentId }) {
  const sessionId = `wecom:${fromUser}`;
  try {
    await execFileAsync("clawdbot", ["session", "clear", "--session-id", sessionId], {
      timeout: 10000,
    });
    await sendWecomText({
      corpId, corpSecret, agentId, toUser: fromUser,
      text: "✅ 会话已清除，我们可以开始新的对话了！",
    });
  } catch (err) {
    api.logger.warn?.(`wecom: failed to clear session: ${err.message}`);
    await sendWecomText({
      corpId, corpSecret, agentId, toUser: fromUser,
      text: "会话已重置，请开始新的对话。",
    });
  }
  return true;
}

async function handleStatusCommand({ api, fromUser, corpId, corpSecret, agentId }) {
  const config = getWecomConfig(api);
  const accountIds = listWecomAccountIds(api);

  const statusText = `📊 系统状态

渠道：企业微信 (WeCom)
会话ID：wecom:${fromUser}
账户ID：${config?.accountId || "default"}
已配置账户：${accountIds.join(", ")}
插件版本：0.3.0

功能状态：
✅ 文本消息
✅ 图片发送/接收
✅ 消息分段 (2048字符)
✅ 命令系统
✅ Markdown 转换
✅ API 限流
✅ 多账户支持`;

  await sendWecomText({ corpId, corpSecret, agentId, toUser: fromUser, text: statusText });
  return true;
}

const COMMANDS = {
  "/help": handleHelpCommand,
  "/clear": handleClearCommand,
  "/status": handleStatusCommand,
};

// 异步处理入站消息 - 使用 gateway 内部 agent runtime API
async function processInboundMessage({ api, fromUser, content, msgType, mediaId, picUrl, recognition, thumbMediaId, fileName, fileSize, linkTitle, linkDescription, linkUrl, linkPicUrl, chatId, isGroupChat }) {
  const config = getWecomConfig(api);
  const cfg = api.config;
  const runtime = api.runtime;

  if (!config?.corpId || !config?.corpSecret || !config?.agentId) {
    api.logger.warn?.("wecom: not configured (check channels.wecom in clawdbot.json)");
    return;
  }

  const { corpId, corpSecret, agentId } = config;

  try {
    // 会话ID：群聊使用 wecom:group:chatId，私聊使用 wecom:userId
    // 注意：sessionKey 需要统一为小写，与 resolveAgentRoute 保持一致
    const sessionId = isGroupChat ? `wecom:group:${chatId}`.toLowerCase() : `wecom:${fromUser}`.toLowerCase();
    api.logger.info?.(`wecom: processing ${msgType} message for session ${sessionId}${isGroupChat ? " (group)" : ""}`);

    // 命令检测（仅对文本消息）
    if (msgType === "text" && content?.startsWith("/")) {
      const commandKey = content.split(/\s+/)[0].toLowerCase();
      const handler = COMMANDS[commandKey];
      if (handler) {
        api.logger.info?.(`wecom: handling command ${commandKey}`);
        await handler({ api, fromUser, corpId, corpSecret, agentId, chatId, isGroupChat });
        return; // 命令已处理，不再调用 AI
      }
    }

    let messageText = content || "";

    // 处理图片消息 - 真正的 Vision 能力
    let imageBase64 = null;
    let imageMimeType = null;

    if (msgType === "image" && mediaId) {
      api.logger.info?.(`wecom: downloading image mediaId=${mediaId}`);

      try {
        // 优先使用 mediaId 下载原图
        const { buffer, contentType } = await downloadWecomMedia({ corpId, corpSecret, mediaId });
        imageBase64 = buffer.toString("base64");
        imageMimeType = contentType || "image/jpeg";
        messageText = "[用户发送了一张图片]";
        api.logger.info?.(`wecom: image downloaded, size=${buffer.length} bytes, type=${imageMimeType}`);
      } catch (downloadErr) {
        api.logger.warn?.(`wecom: failed to download image via mediaId: ${downloadErr.message}`);

        // 降级：尝试通过 PicUrl 下载
        if (picUrl) {
          try {
            const { buffer, contentType } = await fetchMediaFromUrl(picUrl);
            imageBase64 = buffer.toString("base64");
            imageMimeType = contentType || "image/jpeg";
            messageText = "[用户发送了一张图片]";
            api.logger.info?.(`wecom: image downloaded via PicUrl, size=${buffer.length} bytes`);
          } catch (picUrlErr) {
            api.logger.warn?.(`wecom: failed to download image via PicUrl: ${picUrlErr.message}`);
            messageText = "[用户发送了一张图片，但下载失败]\n\n请告诉用户图片处理暂时不可用。";
          }
        } else {
          messageText = "[用户发送了一张图片，但下载失败]\n\n请告诉用户图片处理暂时不可用。";
        }
      }
    }

    // 处理语音消息
    if (msgType === "voice" && mediaId) {
      api.logger.info?.(`wecom: received voice message mediaId=${mediaId}`);

      // 企业微信开启语音识别后，Recognition 字段会包含转写结果
      if (recognition) {
        api.logger.info?.(`wecom: voice recognition result: ${recognition.slice(0, 50)}...`);
        messageText = `[语音消息] ${recognition}`;
      } else {
        // 没有开启语音识别，提示用户
        messageText = "[用户发送了一条语音消息]\n\n请告诉用户目前暂不支持语音消息，建议发送文字消息。";
      }
    }

    // 处理视频消息
    if (msgType === "video" && mediaId) {
      api.logger.info?.(`wecom: received video message mediaId=${mediaId}`);
      try {
        const { buffer, contentType } = await downloadWecomMedia({ corpId, corpSecret, mediaId });
        const tempDir = join(tmpdir(), "clawdbot-wecom");
        await mkdir(tempDir, { recursive: true });
        const videoTempPath = join(tempDir, `video-${Date.now()}-${Math.random().toString(36).slice(2)}.mp4`);
        await writeFile(videoTempPath, buffer);
        api.logger.info?.(`wecom: saved video to ${videoTempPath}, size=${buffer.length} bytes`);
        messageText = `[用户发送了一个视频文件，已保存到: ${videoTempPath}]\n\n请告知用户您已收到视频。`;
      } catch (downloadErr) {
        api.logger.warn?.(`wecom: failed to download video: ${downloadErr.message}`);
        messageText = "[用户发送了一个视频，但下载失败]\n\n请告诉用户视频处理暂时不可用。";
      }
    }

    // 处理文件消息
    if (msgType === "file" && mediaId) {
      api.logger.info?.(`wecom: received file message mediaId=${mediaId}, fileName=${fileName}, size=${fileSize}`);
      try {
        const { buffer, contentType } = await downloadWecomMedia({ corpId, corpSecret, mediaId });
        const ext = fileName ? fileName.split('.').pop() : 'bin';
        const safeFileName = fileName || `file-${Date.now()}.${ext}`;
        const tempDir = join(tmpdir(), "clawdbot-wecom");
        await mkdir(tempDir, { recursive: true });
        const fileTempPath = join(tempDir, `${Date.now()}-${safeFileName}`);
        await writeFile(fileTempPath, buffer);
        api.logger.info?.(`wecom: saved file to ${fileTempPath}, size=${buffer.length} bytes`);

        const readableTypes = ['.txt', '.md', '.json', '.xml', '.csv', '.log', '.pdf'];
        const isReadable = readableTypes.some(t => safeFileName.toLowerCase().endsWith(t));

        if (isReadable) {
          messageText = `[用户发送了一个文件: ${safeFileName}，已保存到: ${fileTempPath}]\n\n请使用 Read 工具查看这个文件的内容。`;
        } else {
          messageText = `[用户发送了一个文件: ${safeFileName}，大小: ${fileSize || buffer.length} 字节，已保存到: ${fileTempPath}]\n\n请告知用户您已收到文件。`;
        }
      } catch (downloadErr) {
        api.logger.warn?.(`wecom: failed to download file: ${downloadErr.message}`);
        messageText = `[用户发送了一个文件${fileName ? `: ${fileName}` : ''}，但下载失败]\n\n请告诉用户文件处理暂时不可用。`;
      }
    }

    // 处理链接分享消息
    if (msgType === "link") {
      api.logger.info?.(`wecom: received link message title=${linkTitle}, url=${linkUrl}`);
      messageText = `[用户分享了一个链接]\n标题: ${linkTitle || '(无标题)'}\n描述: ${linkDescription || '(无描述)'}\n链接: ${linkUrl || '(无链接)'}\n\n请根据链接内容回复用户。如需要，可以使用 WebFetch 工具获取链接内容。`;
    }

    if (!messageText) {
      api.logger.warn?.("wecom: empty message content");
      return;
    }

    // 如果有图片，保存到临时文件供 AI 读取
    let imageTempPath = null;
    if (imageBase64 && imageMimeType) {
      try {
        const ext = imageMimeType.includes("png") ? "png" : imageMimeType.includes("gif") ? "gif" : "jpg";
        const tempDir = join(tmpdir(), "clawdbot-wecom");
        await mkdir(tempDir, { recursive: true });
        imageTempPath = join(tempDir, `image-${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`);
        await writeFile(imageTempPath, Buffer.from(imageBase64, "base64"));
        api.logger.info?.(`wecom: saved image to ${imageTempPath}`);
        // 更新消息文本，告知 AI 图片位置
        messageText = `[用户发送了一张图片，已保存到: ${imageTempPath}]\n\n请使用 Read 工具查看这张图片并描述内容。`;
      } catch (saveErr) {
        api.logger.warn?.(`wecom: failed to save image: ${saveErr.message}`);
        messageText = "[用户发送了一张图片，但保存失败]\n\n请告诉用户图片处理暂时不可用。";
        imageTempPath = null;
      }
    }

    // 获取路由信息
    const route = runtime.channel.routing.resolveAgentRoute({
      cfg,
      sessionKey: sessionId,
      channel: "wecom",
      accountId: config.accountId || "default",
    });

    // 获取 storePath
    const storePath = runtime.channel.session.resolveStorePath(cfg.session?.store, {
      agentId: route.agentId,
    });

    // 格式化消息体
    const envelopeOptions = runtime.channel.reply.resolveEnvelopeFormatOptions(cfg);
    const body = runtime.channel.reply.formatInboundEnvelope({
      channel: "WeCom",
      from: fromUser,
      timestamp: Date.now(),
      body: messageText,
      chatType: isGroupChat ? "group" : "direct",
      sender: {
        name: fromUser,
        id: fromUser,
      },
      ...envelopeOptions,
    });

    // 构建 Session 上下文对象
    const ctxPayload = {
      Body: body,
      RawBody: content || "",
      From: isGroupChat ? `wecom:group:${chatId}` : `wecom:${fromUser}`,
      To: `wecom:${fromUser}`,
      SessionKey: sessionId,
      AccountId: config.accountId || "default",
      ChatType: isGroupChat ? "group" : "direct",
      ConversationLabel: fromUser,
      SenderName: fromUser,
      SenderId: fromUser,
      Provider: "wecom",
      Surface: "wecom",
      MessageSid: `wecom-${Date.now()}`,
      Timestamp: Date.now(),
      OriginatingChannel: "wecom",
      OriginatingTo: `wecom:${fromUser}`,
    };

    // 注册会话到 Sessions UI
    await runtime.channel.session.recordInboundSession({
      storePath,
      sessionKey: sessionId,
      ctx: ctxPayload,
      updateLastRoute: !isGroupChat ? {
        sessionKey: sessionId,
        channel: "wecom",
        to: fromUser,
        accountId: config.accountId || "default",
      } : undefined,
      onRecordError: (err) => {
        api.logger.warn?.(`wecom: failed to record session: ${err}`);
      },
    });
    api.logger.info?.(`wecom: session registered for ${sessionId}`);

    // 记录渠道活动
    runtime.channel.activity.record({
      channel: "wecom",
      accountId: config.accountId || "default",
      direction: "inbound",
    });

    // 写入用户消息到 transcript 文件（使 Chat UI 可以显示历史）
    await writeToTranscript({
      sessionKey: sessionId,
      role: "user",
      text: messageText,
      logger: api.logger,
    });

    // 广播用户消息到 Chat UI
    const inboundRunId = `wecom-inbound-${Date.now()}`;
    broadcastToChatUI({
      sessionKey: sessionId,
      role: "user",
      text: messageText,
      runId: inboundRunId,
      state: "final",
    });

    api.logger.info?.(`wecom: dispatching message via agent runtime for session ${sessionId}`);

    // 使用 gateway 内部 agent runtime API 调用 AI
    // 对标 Telegram 的 dispatchReplyWithBufferedBlockDispatcher
    const chunkMode = runtime.channel.text.resolveChunkMode(cfg, "wecom", config.accountId || "default");
    const tableMode = runtime.channel.text.resolveMarkdownTableMode({
      cfg,
      channel: "wecom",
      accountId: config.accountId || "default",
    });

    try {
      const outboundRunId = `wecom-outbound-${Date.now()}`;
      await runtime.channel.reply.dispatchReplyWithBufferedBlockDispatcher({
        ctx: ctxPayload,
        cfg,
        dispatcherOptions: {
          deliver: async (payload, info) => {
            // 发送回复到企业微信
            if (payload.text) {
              api.logger.info?.(`wecom: delivering ${info.kind} reply, length=${payload.text.length}`);
              // 应用 Markdown 转换
              const formattedReply = markdownToWecomText(payload.text);
              await sendWecomText({
                corpId,
                corpSecret,
                agentId,
                toUser: fromUser,
                text: formattedReply,
                logger: api.logger,
              });
              api.logger.info?.(`wecom: sent AI reply to ${fromUser}: ${formattedReply.slice(0, 50)}...`);

              // 写入 AI 回复到 transcript 文件（使 Chat UI 可以显示历史）
              await writeToTranscript({
                sessionKey: sessionId,
                role: "assistant",
                text: payload.text,
                logger: api.logger,
              });

              // 广播 AI 回复到 Chat UI
              broadcastToChatUI({
                sessionKey: sessionId,
                role: "assistant",
                text: payload.text,
                runId: outboundRunId,
                state: info.kind === "final" ? "final" : "streaming",
              });
            }
          },
          onError: (err, info) => {
            api.logger.error?.(`wecom: ${info.kind} reply failed: ${String(err)}`);
          },
        },
        replyOptions: {
          // 禁用流式响应，因为企业微信不支持编辑消息
          disableBlockStreaming: true,
        },
      });
    } finally {
      // 清理临时图片文件
      if (imageTempPath) {
        unlink(imageTempPath).catch(() => {});
      }
    }

  } catch (err) {
    api.logger.error?.(`wecom: failed to process message: ${err.message}`);
    api.logger.error?.(`wecom: stack trace: ${err.stack}`);

    // 发送错误提示给用户
    try {
      await sendWecomText({
        corpId,
        corpSecret,
        agentId,
        toUser: fromUser,
        text: `抱歉，处理您的消息时出现错误，请稍后重试。\n错误: ${err.message?.slice(0, 100) || "未知错误"}`,
        logger: api.logger,
      });
    } catch (sendErr) {
      api.logger.error?.(`wecom: failed to send error message: ${sendErr.message}`);
      api.logger.error?.(`wecom: send error stack: ${sendErr.stack}`);
      api.logger.error?.(`wecom: original error was: ${err.message}`);
    }
  }
}
