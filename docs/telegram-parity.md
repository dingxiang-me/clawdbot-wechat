# Telegram parity checklist (target: OpenClaw-Wechat)

目标：对标 OpenClaw 的 Telegram channel 行为，把 WeCom 插件迭代到同等级可用性。

## A. 路由与会话（Routing & Sessions）
- [ ] DM 与群聊的 sessionKey 规则与隔离策略明确（类似 Telegram：DM 主会话 / 群聊隔离）
- [ ] group 允许列表（allowlist）与 mention gating（requireMention）可配置
- [ ] 每条入站消息都记录 session（UI 可见、可追踪）

## B. 入站消息标准化（Inbound Envelope）
- [ ] 文本消息 → 统一 envelope
- [ ] 图片/文件/视频/语音 → 统一 envelope + media placeholder（可被 agent 读取/下载）
- [ ] 长消息/堆栈粘贴 → 不崩溃、不会破坏 session（UTF-8/边界处理）

## C. 出站发送（Outbound）
- [ ] 文本：自动分段（按字节限制），失败降级
- [ ] 图片：上传临时素材 → 发送
- [ ] 文件：上传临时素材 → 发送
- [ ] （可选）markdown：转换成企业微信可读格式（已实现基本版）

## D. 命令与交互（Commands）
- [ ] /help
- [ ] /status
- [ ] /clear
- [ ] 群聊激活模式（always/mention）至少具备 config 层持久化

## E. 可观测性（Observability）
- [ ] 关键日志：registered webhook / inbound / dispatch / outbound deliver / errors
- [ ] 自检命令：env 齐全 + 路由路径 + 关键函数可调用（已实现基础版 wecom:selfcheck）
- [ ] 失败时给用户可理解的提示（不要 silent fail）

## F. 本地测试（Local Test Harness）
- [ ] 纯函数单测：签名校验、AES 解密、XML parse
- [ ] 回放测试：给定加密 XML payload → 走 handler → 断言调用链（不依赖真实 WeCom）
- [ ] CI 跑测试（已接入 CI 框架，待补测试）
