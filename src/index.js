import crypto from "node:crypto";
import { XMLParser, XMLBuilder } from "fast-xml-parser";
import { normalizePluginHttpPath } from "clawdbot/plugin-sdk";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const xmlParser = new XMLParser({ ignoreAttributes: false, trimValues: true });
const xmlBuilder = new XMLBuilder({ ignoreAttributes: false });

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
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

// 企业微信 access_token 缓存
let accessTokenCache = { token: null, expiresAt: 0 };

async function getWecomAccessToken({ corpId, corpSecret }) {
  const now = Date.now();
  if (accessTokenCache.token && accessTokenCache.expiresAt > now + 60000) {
    return accessTokenCache.token;
  }

  const tokenUrl = `https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=${encodeURIComponent(corpId)}&corpsecret=${encodeURIComponent(corpSecret)}`;
  const tokenRes = await fetch(tokenUrl);
  const tokenJson = await tokenRes.json();
  if (!tokenJson?.access_token) {
    throw new Error(`WeCom gettoken failed: ${JSON.stringify(tokenJson)}`);
  }

  accessTokenCache = {
    token: tokenJson.access_token,
    expiresAt: now + (tokenJson.expires_in || 7200) * 1000,
  };

  return accessTokenCache.token;
}

async function sendWecomText({ corpId, corpSecret, agentId, toUser, text }) {
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
    chatTypes: ["direct"],
    media: {
      inbound: true,
      outbound: true,
    },
    markdown: true,
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
      const corpId = requireEnv("WECOM_CORP_ID");
      const corpSecret = requireEnv("WECOM_CORP_SECRET");
      const agentId = asNumber(requireEnv("WECOM_AGENT_ID"));
      if (!corpId || !corpSecret || !agentId) {
        return { ok: false, error: new Error("Missing WECOM_CORP_ID/WECOM_CORP_SECRET/WECOM_AGENT_ID") };
      }
      await sendWecomText({ corpId, corpSecret, agentId, toUser: to, text });
      return { ok: true, provider: "wecom" };
    },
  },
  // 入站消息处理 - clawdbot 会调用这个方法
  inbound: {
    // 当消息需要回复时，clawdbot 会调用这个方法
    deliverReply: async ({ to, text, accountId }) => {
      const corpId = requireEnv("WECOM_CORP_ID");
      const corpSecret = requireEnv("WECOM_CORP_SECRET");
      const agentId = asNumber(requireEnv("WECOM_AGENT_ID"));
      if (!corpId || !corpSecret || !agentId) {
        throw new Error("Missing WECOM_CORP_ID/WECOM_CORP_SECRET/WECOM_AGENT_ID");
      }
      // to 格式为 "wecom:userid"，需要提取 userid
      const userId = to.startsWith("wecom:") ? to.slice(6) : to;
      await sendWecomText({ corpId, corpSecret, agentId, toUser: userId, text });
      return { ok: true };
    },
  },
};

// 存储 runtime 引用以便在消息处理中使用
let gatewayRuntime = null;

export default function register(api) {
  // 保存 runtime 引用
  gatewayRuntime = api.runtime;

  api.registerChannel({ plugin: WecomChannelPlugin });

  const webhookPath = requireEnv("WECOM_WEBHOOK_PATH", "/wecom/callback");
  const normalizedPath = normalizePluginHttpPath(webhookPath, "/wecom/callback") ?? "/wecom/callback";

  api.registerHttpRoute({
    path: normalizedPath,
    handler: async (req, res) => {
      const token = requireEnv("WECOM_CALLBACK_TOKEN");
      const aesKey = requireEnv("WECOM_CALLBACK_AES_KEY");

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

      api.logger.info?.(
        `wecom inbound: FromUserName=${msgObj?.FromUserName} MsgType=${msgObj?.MsgType} Content=${(msgObj?.Content ?? "").slice?.(0, 80)}`
      );

      const fromUser = msgObj.FromUserName;
      const msgType = msgObj.MsgType;

      // 异步处理消息，不阻塞响应
      if (msgType === "text" && msgObj?.Content) {
        processInboundMessage({ api, fromUser, content: msgObj.Content, msgType: "text" }).catch((err) => {
          api.logger.error?.(`wecom: async message processing failed: ${err.message}`);
        });
      } else if (msgType === "image" && msgObj?.MediaId) {
        processInboundMessage({ api, fromUser, mediaId: msgObj.MediaId, msgType: "image", picUrl: msgObj.PicUrl }).catch((err) => {
          api.logger.error?.(`wecom: async image processing failed: ${err.message}`);
        });
      } else if (msgType === "voice" && msgObj?.MediaId) {
        processInboundMessage({ api, fromUser, mediaId: msgObj.MediaId, msgType: "voice" }).catch((err) => {
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

// 异步处理入站消息
async function processInboundMessage({ api, fromUser, content, msgType, mediaId, picUrl }) {
  const corpId = requireEnv("WECOM_CORP_ID");
  const corpSecret = requireEnv("WECOM_CORP_SECRET");
  const agentId = asNumber(requireEnv("WECOM_AGENT_ID"));

  if (!corpId || !corpSecret || !agentId) {
    api.logger.warn?.("wecom: missing WECOM_CORP_ID/WECOM_CORP_SECRET/WECOM_AGENT_ID");
    return;
  }

  try {
    const sessionId = `wecom:${fromUser}`;
    api.logger.info?.(`wecom: processing ${msgType} message for session ${sessionId}`);

    let messageText = content || "";

    // 处理图片消息
    if (msgType === "image" && mediaId) {
      api.logger.info?.(`wecom: downloading image mediaId=${mediaId}`);

      // 对于图片，我们可以使用 PicUrl（如果有的话）或者下载媒体文件
      // PicUrl 是图片的临时链接，可以直接访问
      if (picUrl) {
        messageText = `[用户发送了一张图片]\n图片链接: ${picUrl}\n\n请描述这张图片的内容。`;
      } else {
        // 如果没有 PicUrl，尝试下载
        try {
          const { buffer, contentType } = await downloadWecomMedia({ corpId, corpSecret, mediaId });
          const base64 = buffer.toString("base64");
          const dataUrl = `data:${contentType || "image/jpeg"};base64,${base64}`;
          messageText = `[用户发送了一张图片]\n图片数据(base64): ${dataUrl.slice(0, 100)}...\n\n请描述这张图片的内容。`;
        } catch (downloadErr) {
          api.logger.warn?.(`wecom: failed to download image: ${downloadErr.message}`);
          messageText = "[用户发送了一张图片，但下载失败]\n\n请告诉用户图片处理暂时不可用。";
        }
      }
    }

    // 处理语音消息
    if (msgType === "voice" && mediaId) {
      api.logger.info?.(`wecom: received voice message mediaId=${mediaId}`);
      messageText = "[用户发送了一条语音消息]\n\n请告诉用户目前暂不支持语音消息，请发送文字。";
    }

    if (!messageText) {
      api.logger.warn?.("wecom: empty message content");
      return;
    }

    api.logger.info?.(`wecom: calling agent for session ${sessionId}`);

    // 使用 clawdbot agent CLI 调用 AI 代理
    const { stdout } = await execFileAsync("clawdbot", [
      "agent",
      "--message", messageText,
      "--session-id", sessionId,
      "--json",
      "--timeout", "120",
    ], {
      timeout: 130000, // 130秒超时
      maxBuffer: 10 * 1024 * 1024, // 10MB
    });

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
      await sendWecomText({
        corpId,
        corpSecret,
        agentId,
        toUser: fromUser,
        text: replyText,
      });
      api.logger.info?.(`wecom: sent AI reply to ${fromUser}: ${replyText.slice(0, 50)}...`);
    } else {
      api.logger.warn?.("wecom: agent returned empty response");
    }
  } catch (err) {
    api.logger.error?.(`wecom: failed to process message: ${err.message}`);

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
    }
  }
}
