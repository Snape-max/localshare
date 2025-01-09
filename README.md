# LocalShare

LocalShare 是一个简单的本地文件共享工具，允许用户通过 HTTP 服务器发送文件，并通过 SSDP 通知接收端发现文件。

## 项目原理

LocalShare 通过以下步骤实现文件共享：

1. **发送模式**：
   - 启动 HTTP 服务器，提供文件下载服务。
   - 发送 SSDP 通知，告知局域网内的接收端有文件可供下载。

2. **接收模式**：
   - 监听 SSDP 通知，发现局域网内的发送端。
   - 通过 HTTP 服务器下载文件。

## 使用方法

### 发送模式

在发送模式下，您可以通过指定文件路径和端口来启动 HTTP 服务器并发送 SSDP 通知。

```sh
localshare --send --file <文件路径> --port <端口>
```

示例：

```sh
localshare --send --file /path/to/file.txt --port 6654
```

### 接收模式
在接收模式下，程序会监听 SSDP 通知并下载文件。

```sh
localshare --receive
```

## 示例

### 发送文件
假设您有一个文件 example.txt，并希望通过端口 6654 共享该文件：

```sh
localshare --send --file example.txt --port 6654
```

### 接收文件
在接收端，您只需运行以下命令来接收文件：

```sh
localshare --receive
```

运行后，接收端会监听 SSDP 通知并下载共享的文件。

## 依赖
- Rust
- Clap
- Crossterm
- Hyper
- Tokio
- Reqwest
- Indicatif
- Urlencoding
- Futures

## 贡献

欢迎提交问题和贡献代码！

## 许可证

本项目基于 MIT 许可证开源。

