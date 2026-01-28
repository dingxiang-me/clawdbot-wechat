import crypto from "node:crypto";
import { XMLParser, XMLBuilder } from "fast-xml-parser";
import { normalizePluginHttpPath } from "clawdbot/plugin-sdk";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile, unlink, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

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

// 企业微信文本消息限制
const WECOM_TEXT_LIMIT = 2048;

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

// 消息分段函数，优先在自然断点处分割
function splitWecomText(text, limit = WECOM_TEXT_LIMIT) {
  if (text.length <= limit) return [text];

  const chunks = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (remaining.length <= limit) {
      chunks.push(remaining);
      break;
    }

    // 优先在段落处分割
    let splitIndex = remaining.lastIndexOf("\n\n", limit);
    // 其次在换行处分割
    if (splitIndex < limit * 0.3) {
      splitIndex = remaining.lastIndexOf("\n", limit);
    }
    // 再次在句号处分割
    if (splitIndex < limit * 0.3) {
      splitIndex = remaining.lastIndexOf("。", limit);
    }
    // 最后在空格处分割
    if (splitIndex < limit * 0.3) {
      splitIndex = remaining.lastIndexOf(" ", limit);
    }
    // 如果都找不到，强制在限制处分割
    if (splitIndex < limit * 0.2) {
      splitIndex = limit;
    }

    chunks.push(remaining.slice(0, splitIndex));
    remaining = remaining.slice(splitIndex).trimStart();
  }

  return chunks;
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
async function sendWecomText({ corpId, corpSecret, agentId, toUser, text }) {
  const chunks = splitWecomText(text);

  for (let i = 0; i < chunks.length; i++) {
    await sendWecomTextSingle({ corpId, corpSecret, agentId, toUser, text: chunks[i] });
    // 分段发送时添加间隔，避免触发限流
    if (i < chunks.length - 1) {
      await sleep(100);
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

// 多账户配置存储
const wecomAccounts = new Map(); // key: accountId, value: config
let defaultAccountId = "default";

// 获取 wecom 配置（支持多账户）
function getWecomConfig(api, accountId = null) {
  const targetAccountId = accountId || defaultAccountId;

  // 如果已缓存，直接返回
  if (wecomAccounts.has(targetAccountId)) {
    return wecomAccounts.get(targetAccountId);
  }

  const cfg = api?.config ?? gatewayRuntime?.config;

  // 尝试从 env.vars 读取配置（支持多账户格式）
  const envVars = cfg?.env?.vars ?? {};

  // 检查是否有账户特定的配置 (WECOM_<ACCOUNT>_CORP_ID 格式)
  const accountPrefix = targetAccountId === "default" ? "WECOM" : `WECOM_${targetAccountId.toUpperCase()}`;

  let corpId = envVars[`${accountPrefix}_CORP_ID`] || (targetAccountId === "default" ? envVars.WECOM_CORP_ID : null);
  let corpSecret = envVars[`${accountPrefix}_CORP_SECRET`] || (targetAccountId === "default" ? envVars.WECOM_CORP_SECRET : null);
  let agentId = envVars[`${accountPrefix}_AGENT_ID`] || (targetAccountId === "default" ? envVars.WECOM_AGENT_ID : null);
  let callbackToken = envVars[`${accountPrefix}_CALLBACK_TOKEN`] || (targetAccountId === "default" ? envVars.WECOM_CALLBACK_TOKEN : null);
  let callbackAesKey = envVars[`${accountPrefix}_CALLBACK_AES_KEY`] || (targetAccountId === "default" ? envVars.WECOM_CALLBACK_AES_KEY : null);
  let webhookPath = envVars[`${accountPrefix}_WEBHOOK_PATH`] || (targetAccountId === "default" ? envVars.WECOM_WEBHOOK_PATH : null) || "/wecom/callback";

  // 回退到进程环境变量
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
  const envVars = cfg?.env?.vars ?? {};

  const accountIds = new Set(["default"]);

  // 查找 WECOM_<ACCOUNT>_CORP_ID 格式的配置
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

// 异步处理入站消息
async function processInboundMessage({ api, fromUser, content, msgType, mediaId, picUrl, recognition, chatId, isGroupChat }) {
  const config = getWecomConfig(api);

  if (!config?.corpId || !config?.corpSecret || !config?.agentId) {
    api.logger.warn?.("wecom: not configured (check channels.wecom in clawdbot.json)");
    return;
  }

  const { corpId, corpSecret, agentId } = config;

  try {
    // 会话ID：群聊使用 wecom:group:chatId，私聊使用 wecom:userId
    const sessionId = isGroupChat ? `wecom:group:${chatId}` : `wecom:${fromUser}`;
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

    if (!messageText) {
      api.logger.warn?.("wecom: empty message content");
      return;
    }

    api.logger.info?.(`wecom: calling agent for session ${sessionId}`);

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

    // 使用 clawdbot agent CLI 调用 AI 代理
    let stdout;
    try {
      const result = await execFileAsync("clawdbot", [
        "agent",
        "--message", messageText,
        "--session-id", sessionId,
        "--json",
        "--timeout", "120",
      ], {
        timeout: 130000, // 130秒超时
        maxBuffer: 10 * 1024 * 1024, // 10MB
      });
      stdout = result.stdout;
    } finally {
      // 清理临时图片文件
      if (imageTempPath) {
        unlink(imageTempPath).catch(() => {});
      }
    }

    // 解析 JSON 输出
    let result;
    try {
      result = JSON.parse(stdout);
    } catch (parseErr) {
      api.logger.warn?.(`wecom: failed to parse agent response as JSON: ${stdout.slice(0, 200)}`);
      // 如果不是 JSON，直接使用输出作为回复
      result = { text: stdout.trim() };
    }

    // 从 clawdbot agent --json 输出中提取回复文本
    // 格式: { result: { payloads: [{ text: "..." }] } }
    let replyText = "";
    if (result?.result?.payloads && Array.isArray(result.result.payloads)) {
      replyText = result.result.payloads
        .map(p => p.text)
        .filter(Boolean)
        .join("\n\n");
    } else if (result?.text) {
      replyText = result.text;
    } else if (result?.content) {
      replyText = result.content;
    } else if (typeof result === "string") {
      replyText = result;
    }

    if (replyText) {
      // 应用 Markdown 转换
      const formattedReply = markdownToWecomText(replyText);
      await sendWecomText({
        corpId,
        corpSecret,
        agentId,
        toUser: fromUser,
        text: formattedReply,
      });
      api.logger.info?.(`wecom: sent AI reply to ${fromUser}: ${formattedReply.slice(0, 50)}...`);
    } else {
      api.logger.warn?.("wecom: agent returned empty response");
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
      });
    } catch (sendErr) {
      api.logger.error?.(`wecom: failed to send error message: ${sendErr.message}`);
      api.logger.error?.(`wecom: send error stack: ${sendErr.stack}`);
      api.logger.error?.(`wecom: original error was: ${err.message}`);
    }
  }
}
