# LocalShare

## 项目简介

LocalShare 是一个简单的本地文件共享工具，允许用户在同一局域网内快速共享文件。它支持两种模式：发送模式和接收模式。发送模式允许用户通过 HTTP 服务器共享文件，并通过 SSDP（简单服务发现协议）广播文件的位置。接收模式则允许用户发现并下载局域网内其他设备共享的文件。

## 原理

LocalShare 的核心原理基于以下技术：

1. **HTTP 文件服务器**：在发送模式下，LocalShare 启动一个 HTTP 服务器，用于提供文件下载服务。文件可以通过 HTTP 协议进行分块下载，支持断点续传。

2. **SSDP（简单服务发现协议）**：LocalShare 使用 SSDP 协议在局域网内广播文件的位置信息。接收端通过监听 SSDP 消息来发现可用的文件共享服务。

3. **多线程与异步编程**：LocalShare 使用多线程和异步编程模型来处理并发任务，如 HTTP 请求、文件下载和用户输入处理。

## 使用方法

### 安装

首先，确保你已经安装了 Rust 编程语言环境。然后，克隆项目并构建：

```bash
git clone https://github.com/Snape-max/localshare.git
cd localshare
cargo build --release
```

### 发送模式

在发送模式下，你可以通过以下命令共享一个文件：

```bash
./localshare --send --file /path/to/your/file.txt --port 8080
```

- `--send`：启用发送模式。
- `--file`：指定要共享的文件路径。
- `--port`：指定 HTTP 服务器的端口号（默认：6654）。
- `--ttl`：指定 SSDP 通知的 TTL（Time To Live，默认：4）。

### 接收模式

在接收模式下，你可以通过以下命令发现并下载局域网内其他设备共享的文件：

```bash
./localshare --receive --chunk 4
```

- `--receive`：启用接收模式。
- `--chunk`：指定下载文件时的分块数量（默认：4）。

### 示例

#### 发送文件

假设你有一个名为 `example.txt` 的文件，你可以通过以下命令共享它：

```bash
./localshare --send --file example.txt --port 8080
```

#### 接收文件

在接收端，你可以运行以下命令来发现并下载共享的文件：

```bash
./localshare --receive --chunk 4
```

运行后，程序会列出所有可用的共享文件。你可以通过输入对应的数字来选择要下载的文件。

## 项目结构

- `src/main.rs`：主程序文件，包含命令行解析、HTTP 服务器、SSDP 通知和文件下载逻辑。
- `Cargo.toml`：项目的依赖和配置。

## 依赖

- `clap`：用于命令行参数解析。
- `hyper`：用于构建 HTTP 服务器。
- `tokio`：用于异步编程。
- `reqwest`：用于 HTTP 客户端请求。
- `indicatif`：用于显示进度条。
- `crossterm`：用于处理终端输入和输出。
- `urlencoding`：用于 URL 编码和解码。

## 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进本项目。

