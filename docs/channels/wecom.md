---
summary: "WeCom (企业微信) channel plugin"
---

# WeCom (企业微信) (plugin)

This channel integrates Clawdbot with WeCom (企业微信) internal apps.

## Status

- Webhook verification: supported (requires Token + EncodingAESKey)
- Inbound messages: WIP
- Outbound: text supported; media/markdown WIP

## Callback URL

Recommended:

- `https://<your-domain>/wecom/callback`

## Security

Store secrets in environment variables or secret files. Do not commit them.

## FAQ

### 回调 URL / 域名（cloudflared funnel 失败怎么办？）

一些环境下，企业微信后台可能会拦截或不稳定访问“临时域名/共享域名”（例如 cloudflared funnel / trycloudflare）。

推荐：**Cloudflare Tunnel + 你自己的域名（非 funnel）**。

大致步骤：
1) `cloudflared tunnel create <name>`
2) `cloudflared tunnel route dns <name> <your-domain>`
3) 把企业微信回调 URL 配为：`https://<your-domain>/wecom/callback`

> 备案说明：如果服务部署在中国大陆机房/云，通常绕不开 ICP；如果部署在境外，通常不需要 ICP，但访问质量取决于网络。
