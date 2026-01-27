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
