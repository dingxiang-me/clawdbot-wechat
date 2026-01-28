# Changelog

All notable changes to this project will be documented in this file.

## [0.3.2] - 2026-01-29

### Added

#### 媒体消息扩展
- **视频消息接收**：支持接收用户发送的视频，自动下载保存到临时目录
- **视频消息发送**：新增 `sendWecomVideo()` 函数，支持发送视频到企业微信
- **文件消息接收**：支持接收用户发送的文件/文档，自动识别可读类型（.txt, .md, .json, .pdf 等）
- **文件消息发送**：新增 `sendWecomFile()` 函数，支持发送文件到企业微信
- **链接分享消息**：支持接收用户分享的链接，提取标题、描述和 URL

#### Chat UI 集成
- **消息同步到 Transcript**：用户消息和 AI 回复写入 session transcript 文件
- **实时广播**：通过 gateway broadcast 实时推送消息到 Chat UI
- **Gateway 方法**：新增 `wecom.init` 和 `wecom.broadcast` 方法

### Changed
- `processInboundMessage()` 函数签名扩展，支持更多消息类型参数
- HTTP 路由处理器新增 video、file、link 类型消息分发

## [0.3.1] - 2026-01-28

### Fixed
- **消息分段按字节计算**：企业微信限制 2048 字节（非字符），中文占 3 字节，修复长消息被截断问题
- **新增 getByteLength() 函数**：精确计算 UTF-8 字节长度
- **二分查找分割点**：使用二分查找算法精确定位字节分割位置

### Added
- **处理状态提示**：收到消息后立即发送"⏳ 收到您的消息，正在处理中，请稍候..."，缓解用户等待焦虑
- **详细调试日志**：记录分段数量、字节长度等信息便于排查问题

## [0.3.0] - 2026-01-28

### Added

#### 阶段一：核心稳定性
- **Token 并发安全**：使用 Promise 锁防止多个请求同时刷新 access_token
- **消息自动分段**：超过 2048 字符的消息自动在自然断点处分割发送
- **XML 安全加固**：禁用实体处理防止 XXE 攻击，添加 1MB 请求体限制
- **错误处理完善**：记录完整堆栈日志，二次发送失败不再吞没异常

#### 阶段二：媒体功能
- **图片上传**：新增 `uploadWecomMedia()` 函数上传临时素材
- **图片发送**：新增 `sendWecomImage()` 函数发送图片消息
- **图片 Vision**：下载用户图片保存到临时文件，AI 可读取分析
- **deliverReply 媒体支持**：支持 `mediaUrl` 和 `mediaType` 参数

#### 阶段三：用户体验
- **命令系统**：支持 `/help`、`/status`、`/clear` 命令
- **Markdown 转换**：AI 回复中的 Markdown 自动转换为可读纯文本格式
- **API 限流**：RateLimiter 类限制并发（最多 3 个）和频率（200ms 间隔）

#### 阶段四：高级功能
- **多账户支持**：Token 缓存按账户隔离，支持 `WECOM_<ACCOUNT>_*` 格式配置
- **语音转文字**：支持企业微信自带语音识别（Recognition 字段）
- **群聊支持**：capabilities 支持 group 类型，群聊会话 ID 格式 `wecom:group:<chatId>`

### Changed
- `capabilities.media.outbound` 改为 `true`
- `capabilities.markdown` 改为 `true`
- `capabilities.chatTypes` 改为 `["direct", "group"]`
- 插件版本升级至 0.3.0

### Fixed
- 修正 capabilities 声明与实际实现不符的问题
- 修复长消息可能导致发送失败的问题

## [0.1.0] - 2026-01-27

### Added
- 初始版本
- 基础文本消息收发
- 消息加解密和签名验证
- access_token 缓存
- 图片消息接收（仅传 URL）
