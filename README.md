# Clawdbot 企业微信插件

> 让你的 Clawdbot AI 助手接入企业微信，通过自建应用实现智能对话。

## 功能特性

- [x] 接收企业微信消息（文本、图片）
- [x] 自动调用 AI 代理处理消息
- [x] 将 AI 回复发送回企业微信用户
- [x] 消息签名验证和 AES 加密解密
- [x] Webhook URL 验证（企业微信回调配置）
- [x] access_token 自动缓存和刷新
- [x] 图片消息识别和描述
- [ ] 语音消息转文字（开发中）
- [ ] 发送图片/文件消息（开发中）
- [ ] Markdown 格式支持（开发中）

## 前置要求

- [Clawdbot](https://clawd.bot) 已安装并配置
- 企业微信管理员权限
- 公网可访问的服务器（用于接收回调）

## 安装

### 方式一：本地路径加载

1. 克隆本仓库：

```bash
git clone https://github.com/YOUR_USERNAME/clawdbot-wecom.git
cd clawdbot-wecom
npm install
```

2. 在 Clawdbot 配置文件 `~/.clawdbot/clawdbot.json` 中添加插件路径：

```json
{
  "plugins": {
    "enabled": true,
    "load": {
      "paths": [
        "/path/to/clawdbot-wecom"
      ]
    }
  }
}
```

### 方式二：npm 安装（即将支持）

```bash
clawdbot plugins install @mijia-life/clawdbot-wecom
```

## 配置

### 第一步：创建企业微信自建应用

1. 登录 [企业微信管理后台](https://work.weixin.qq.com/wework_admin/frame)
2. 进入 **应用管理** → **自建** → **创建应用**
3. 填写应用名称、Logo、可见范围等信息
4. 创建完成后，记录以下信息：
   - **AgentId**：应用的 AgentId
   - **Secret**：应用的 Secret

### 第二步：获取企业信息

1. 在管理后台首页，点击 **我的企业**
2. 记录 **企业ID (CorpId)**

### 第三步：配置接收消息

1. 进入你创建的应用 → **接收消息** → **设置API接收**
2. 填写：
   - **URL**：`https://你的域名/wecom/callback`
   - **Token**：自定义一个 Token（随机字符串）
   - **EncodingAESKey**：点击随机生成
3. 先不要保存！需要先启动 Clawdbot 服务

### 第四步：配置环境变量

在 `~/.clawdbot/clawdbot.json` 中添加环境变量：

```json
{
  "env": {
    "vars": {
      "WECOM_CORP_ID": "你的企业ID",
      "WECOM_CORP_SECRET": "你的应用Secret",
      "WECOM_AGENT_ID": "你的应用AgentId",
      "WECOM_CALLBACK_TOKEN": "你设置的Token",
      "WECOM_CALLBACK_AES_KEY": "你生成的EncodingAESKey",
      "WECOM_WEBHOOK_PATH": "/wecom/callback"
    }
  }
}
```

或者使用 `.env` 文件（参考 `.env.example`）。

### 第五步：配置公网访问

企业微信需要能够访问你的回调 URL。推荐使用 Cloudflare Tunnel：

```bash
# 安装 cloudflared
brew install cloudflared

# 创建隧道
cloudflared tunnel create clawdbot

# 配置隧道路由
cloudflared tunnel route dns clawdbot 你的域名

# 创建配置文件 /etc/cloudflared/config.yml
tunnel: YOUR_TUNNEL_ID
credentials-file: ~/.cloudflared/YOUR_TUNNEL_ID.json
protocol: http2

ingress:
  - hostname: 你的域名
    path: /wecom/callback
    service: http://127.0.0.1:8885
  - service: http_status:404

# 启动隧道
cloudflared tunnel run clawdbot
```

### 第六步：启动并验证

1. 重启 Clawdbot Gateway：

```bash
launchctl kickstart -k gui/501/com.clawdbot.gateway
```

2. 检查插件是否加载：

```bash
clawdbot plugins list
```

3. 回到企业微信管理后台，点击保存回调配置
4. 如果验证通过，配置完成！

## 使用

配置完成后，企业微信用户可以直接向应用发送消息：

1. 在企业微信中找到你创建的应用
2. 发送文字或图片消息
3. AI 会自动回复

### 支持的消息类型

| 类型 | 接收 | 发送 | 说明 |
|------|------|------|------|
| 文本 | ✅ | ✅ | 完全支持 |
| 图片 | ✅ | ❌ | 接收后由 AI 识别描述 |
| 语音 | ⚠️ | ❌ | 接收但暂不处理 |
| 视频 | ❌ | ❌ | 暂不支持 |
| 文件 | ❌ | ❌ | 暂不支持 |

## 环境变量说明

| 变量名 | 必填 | 说明 |
|--------|------|------|
| `WECOM_CORP_ID` | 是 | 企业微信企业ID |
| `WECOM_CORP_SECRET` | 是 | 自建应用的 Secret |
| `WECOM_AGENT_ID` | 是 | 自建应用的 AgentId |
| `WECOM_CALLBACK_TOKEN` | 是 | 回调配置的 Token |
| `WECOM_CALLBACK_AES_KEY` | 是 | 回调配置的 EncodingAESKey |
| `WECOM_WEBHOOK_PATH` | 否 | Webhook 路径，默认 `/wecom/callback` |

## 故障排查

### 回调验证失败

1. 检查 URL 是否可公网访问：
```bash
curl https://你的域名/wecom/callback
# 应返回 "wecom webhook ok"
```

2. 检查环境变量是否正确配置

3. 查看 Clawdbot 日志：
```bash
clawdbot logs -f
```

### 消息没有回复

1. 检查日志中是否有 `wecom inbound` 记录
2. 确认 AI 模型配置正确
3. 检查是否有错误日志

### access_token 获取失败

1. 确认 `WECOM_CORP_ID` 和 `WECOM_CORP_SECRET` 正确
2. 检查应用的可见范围是否包含测试用户
3. 确认服务器能访问 `qyapi.weixin.qq.com`

## 开发

```bash
# 安装依赖
npm install

# 查看日志
clawdbot logs -f | grep wecom

# 重启网关（修改代码后）
launchctl kickstart -k gui/501/com.clawdbot.gateway
```

## 技术实现

- **消息加解密**：使用 AES-256-CBC 算法，遵循企业微信加密规范
- **签名验证**：SHA1 签名验证，防止消息伪造
- **异步处理**：消息接收后立即返回 200，异步调用 AI 处理
- **Token 缓存**：access_token 自动缓存，过期前 1 分钟刷新

## 相关链接

- [Clawdbot 官网](https://clawd.bot)
- [企业微信开发文档](https://developer.work.weixin.qq.com/document/)
- [企业微信消息加解密说明](https://developer.work.weixin.qq.com/document/path/90968)

## 许可证

MIT

## 贡献

欢迎提交 Issue 和 Pull Request！

## 致谢

本插件由 [Clawdbot](https://clawd.bot) 社区开发维护。
