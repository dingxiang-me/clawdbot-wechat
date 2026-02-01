# 部署与公网接入（WeCom 回调）

> 目标：让企业微信能够访问到你的回调 URL：`https://<your-domain>/wecom/callback`

## 推荐方案：Cloudflare Tunnel + 自己域名（非 funnel）

为什么：临时公共域名（例如 cloudflared funnel / trycloudflare）在部分情况下会被拦截或不稳定；用自己域名更可控。

### 1) 前置条件
- 你有一个域名，并托管在 Cloudflare
- 你能在部署机上运行 `cloudflared`

### 2) 创建 tunnel 并绑定域名
```bash
brew install cloudflared

cloudflared tunnel create clawdbot
cloudflared tunnel route dns clawdbot <your-domain>
```

### 3) 配置 tunnel 转发到你的 Clawdbot HTTP 服务
创建 `~/.cloudflared/config.yml`（示例）：
```yaml
tunnel: clawdbot
credentials-file: /path/to/<tunnel-id>.json

ingress:
  - hostname: <your-domain>
    service: http://localhost:3000
  - service: http_status:404
```

然后运行：
```bash
cloudflared tunnel run clawdbot
```

> `3000` 请替换成你实际的 Clawdbot HTTP 端口。

### 4) 企业微信后台填写回调
- URL：`https://<your-domain>/wecom/callback`
- Token：自定义
- EncodingAESKey：随机生成

## 日志排障
- URL 校验失败：检查路径、Token/AESKey 是否一致、公网 HTTPS 是否可访问。
- 收不到消息：确认应用可见范围、是否启用接收消息、回调是否保存成功。
