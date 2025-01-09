use clap::{ArgGroup, Parser, CommandFactory};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;  // 引入 tokio 的通道
use ctrlc;
use hostname::get as get_hostname;
use reqwest::Client;  // 使用 reqwest 的异步客户端
use std::io::Write;
use indicatif::{ProgressBar, ProgressStyle};  // 进度条
use urlencoding::{encode, decode};  // URL 编码和解码
use futures::StreamExt;  // 引入 StreamExt 以使用 next() 方法
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{Clear, ClearType};  // 引入清屏功能
use crossterm::execute;  // 引入执行终端命令的功能

#[derive(Parser, Debug)]
#[clap(name = "localshare", author = "Luke", version = "1.0", about = "A simple local file sharing tool.", long_about = None)]
#[clap(group(
    ArgGroup::new("mode")
        .args(&["receive", "send"]),
))]
struct Cli {
    /// 发送模式
    #[clap(short, long, help = "Enable send mode")]
    send: bool,

    /// 接收模式
    #[clap(short, long, help = "Enable receive mode")]
    receive: bool,

    /// 文件路径（仅在发送模式下使用）
    #[clap(short, long, value_name = "FILE", help = "Path to the file to send", requires = "mode")]
    file: Option<PathBuf>,

    /// HTTP 服务器端口（仅在发送模式下使用）
    #[clap(short, long, value_name = "PORT", help = "Port for the HTTP server (default: 6654)", default_value = "6654")]
    port: u16,
}

/// 获取本地 IP 地址
fn get_local_ip() -> String {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Could not bind socket");
    socket.connect("8.8.8.8:80").expect("Could not connect to server");
    socket.local_addr().unwrap().ip().to_string()
}

/// HTTP 文件服务处理函数
async fn file_handler(file_path: Arc<PathBuf>, file_name: Arc<String>, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    if req.uri().path() == "/file" {
        // 打开文件
        if let Ok(mut file) = File::open(&*file_path).await {
            let mut contents = Vec::new();
            if file.read_to_end(&mut contents).await.is_ok() {
                // 设置响应头，指定下载文件名（URL 编码）
                let encoded_file_name = encode(&file_name);
                let response = Response::builder()
                    .header("Content-Disposition", format!("attachment; filename=\"{}\"", encoded_file_name))
                    .body(Body::from(contents))
                    .unwrap();
                return Ok(response);
            }
        }
        // 文件读取失败
        Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Failed to read file"))
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))
            .unwrap())
    }
}

/// 检查文件是否存在
fn check_file_exists(file_path: &PathBuf) -> bool {
    if file_path.exists() {
        true
    } else {
        eprintln!("Error: File '{}' does not exist.", file_path.display());
        false
    }
}

/// 启动 HTTP 文件服务
async fn start_http_server(file_path: PathBuf, port: u16, stop_signal: Arc<AtomicBool>) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let file_path = Arc::new(file_path);
    let file_name = Arc::new(file_path.file_name().unwrap().to_string_lossy().to_string());

    // 克隆 file_name 用于打印
    let file_name_for_print = file_name.clone();

    let make_svc = make_service_fn(move |_conn| {
        let file_path = file_path.clone();
        let file_name = file_name.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| file_handler(file_path.clone(), file_name.clone(), req)))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("HTTP server running on http://{}:{}/file", get_local_ip(), port);
    println!("Sharing file: {}, waiting for connect.", file_name_for_print);

    // 监听停止信号
    tokio::spawn(async move {
        while !stop_signal.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!("HTTP server shutting down...");
    });

    if let Err(e) = server.await {
        eprintln!("HTTP server error: {}", e);
    }
}

/// 发送 SSDP 通知
fn send_ssdp_notifications(port: u16, stop_signal: Arc<AtomicBool>, device_name: String) {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Could not bind socket");
    socket.set_broadcast(true).expect("set_broadcast failed");
    socket.set_ttl(2).expect("set_ttl failed");

    let target: SocketAddr = "239.255.255.250:1900".parse().unwrap();
    let local_ip = get_local_ip();

    loop {
        if stop_signal.load(Ordering::Relaxed) {
            println!("SSDP notification thread shutting down...");
            break;
        }

        let request = format!(
            "NOTIFY * HTTP/1.1\r\n\
             HOST: 239.255.255.250:1900\r\n\
             CACHE-CONTROL: max-age=1800\r\n\
             LOCATION: http://{}:{}/file\r\n\
             NT: upnp:localshare\r\n\
             NTS: ssdp:alive\r\n\
             SERVER: localshare/1.0\r\n\
             USN: uuid:{}\r\n\r\n",
            local_ip, port, device_name
        );

        match socket.send_to(request.as_bytes(), target) {
            Ok(_) => (),
            Err(e) => eprintln!("Failed to send SSDP notification: {}", e),
        }

        thread::sleep(Duration::from_secs(5));
    }
}


/// 接收端模式
async fn receive_mode() {
    let socket = UdpSocket::bind("0.0.0.0:1900").expect("Could not bind socket");
    socket.join_multicast_v4(&Ipv4Addr::new(239, 255, 255, 250), &Ipv4Addr::new(0, 0, 0, 0))
        .expect("Could not join multicast group");

    let mut buffer = [0; 1024];
    let mut devices = Vec::new();
    let mut last_devices_len = 0;  // 缓存上一次的设备列表长度

    println!("Listening for senders... (Press 'q' to quit)");

    // 创建一个通道用于接收用户输入
    let (tx, mut rx) = mpsc::channel(32);

    // 启动异步任务监听用户输入
    tokio::spawn(async move {
        loop {
            if let Ok(event) = event::read() {
                if let Event::Key(key_event) = event {
                    if let KeyCode::Char(c) = key_event.code {
                        if tx.send(c).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });

    // 主循环
    loop {
        // 设置超时时间为 100ms，以便能够及时处理用户输入
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();

        // 监听 SSDP 消息
        if let Ok((size, _)) = socket.recv_from(&mut buffer) {
            let message = String::from_utf8_lossy(&buffer[..size]);
            if message.contains("SERVER: localshare/1.0") {
                let device_name = extract_field(&message, "USN: uuid:");
                let location = extract_field(&message, "LOCATION: ");

                if !device_name.is_empty() && !location.is_empty() {
                    let device_info = (device_name.clone(), location.clone());
                    if !devices.contains(&device_info) {
                        devices.push(device_info.clone());
                    }
                }
            }
        }

        // 如果设备列表发生变化，更新显示
        if devices.len() != last_devices_len {
            // 清空之前的设备列表显示
            execute!(std::io::stdout(), Clear(ClearType::FromCursorDown)).unwrap();

            // 显示设备列表
            if !devices.is_empty() {
                println!("\nSelect a device to download from:");
                for (i, (device_name, location)) in devices.iter().enumerate() {
                    println!("{}. Device: {}, Location: {}", i + 1, device_name, location);
                }
            }

            // 更新缓存的设备列表长度
            last_devices_len = devices.len();
        }

        // 检查用户输入
        if let Ok(c) = rx.try_recv() {
            match c {
                'q' => {
                    println!("Exiting...");
                    break;
                }
                c if c.is_digit(10) => {
                    let choice = c.to_digit(10).unwrap() as usize;
                    if choice > 0 && choice <= devices.len() {
                        let (device_name, location) = &devices[choice - 1];
                        println!("Downloading from device: {}", device_name);

                        // 下载文件
                        download_file(location).await;
                    } else {
                        println!("Invalid choice.");
                    }
                }
                _ => {}
            }
        }
    }
}


/// 从 SSDP 消息中提取字段
fn extract_field(message: &str, field: &str) -> String {
    message
        .lines()
        .find(|line| line.starts_with(field))
        .map(|line| line.trim_start_matches(field).trim().to_string())
        .unwrap_or_default()
}

/// 下载文件
async fn download_file(url: &str) {
    let client = Client::new();
    if let Ok(response) = client.get(url).send().await {
        // 从响应头中提取文件名
        let file_name = response
            .headers()
            .get("Content-Disposition")
            .and_then(|header| {
                header
                    .to_str()
                    .ok()
                    .and_then(|s| {
                        s.find("filename=")
                            .map(|pos| s[pos + 9..].trim_matches('"').to_string())
                    })
            })
            .unwrap_or_else(|| {
                // 如果未找到文件名，从 URL 中提取
                url.split('/').last().unwrap_or("file").to_string()
            });

        // 解码文件名
        let decoded_file_name = decode(&file_name).expect("Failed to decode file name");

        // 获取文件大小
        let total_size = response.content_length().unwrap_or(0);

        // 创建进度条
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .expect("Failed to set progress bar template")
                .progress_chars("#>-")
        );

        // 保存文件
        if let Ok(mut file) = std::fs::File::create(&*decoded_file_name) {
            let mut downloaded: u64 = 0;
            let mut stream = response.bytes_stream();

            // 逐块读取数据
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.expect("Failed to read chunk");
                file.write_all(&chunk).expect("Failed to write to file");
                downloaded += chunk.len() as u64;
                pb.set_position(downloaded);
            }

            pb.finish_with_message(format!("Downloaded {}", decoded_file_name));
        } else {
            eprintln!("Failed to create file: {}", decoded_file_name);
        }
    } else {
        eprintln!("Failed to download file from {}", url);
    }
    exit(0);
}

fn main() {
    let args = Cli::parse();

    // 如果没有提供 --send 或 --receive 参数，打印帮助信息并退出
    if !args.send && !args.receive {
        let mut cmd = Cli::command();
        cmd.print_help().unwrap();
        return;
    }

    // 创建一个原子布尔值，用于通知线程退出
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_clone = stop_signal.clone();

    // 设置 Ctrl+C 信号处理
    ctrlc::set_handler(move || {
        println!("Shutting down...");
        stop_signal_clone.store(true, Ordering::Relaxed);
        exit(0);
    })
    .expect("Failed to set Ctrl+C handler");

    if args.send {
        if let Some(file) = args.file {
            // 检查文件是否存在
            if !check_file_exists(&file) {
                return;
            }

            // 获取主机名作为设备名
            let device_name = get_hostname().unwrap_or_else(|_| "unknown".into())
            .into_string()
            .unwrap_or_else(|_| "unknown".to_string());

            // 启动 HTTP 文件服务线程
            let file_clone = file.clone();
            let port = args.port;
            let stop_signal_http = stop_signal.clone();
            let http_handle = thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(start_http_server(file_clone, port, stop_signal_http));
            });

            // 启动 SSDP 通知线程
            let stop_signal_ssdp = stop_signal.clone();
            let ssdp_handle = thread::spawn(move || {
                send_ssdp_notifications(port, stop_signal_ssdp, device_name);
            });

            // 等待线程完成
            http_handle.join().unwrap();
            ssdp_handle.join().unwrap();
        } else {
            eprintln!("Error: --file is required in send mode.");
        }
    } else if args.receive {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(receive_mode());
    }

    return;
}