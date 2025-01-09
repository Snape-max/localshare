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
use ctrlc;
use hostname::get as get_hostname;
use reqwest::blocking::get;
use std::io::{self, Write};

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
                // 设置响应头，指定下载文件名
                let response = Response::builder()
                    .header("Content-Disposition", format!("attachment; filename=\"{}\"", file_name))
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
        // 路径不匹配
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
fn receive_mode() {
    let socket = UdpSocket::bind("0.0.0.0:1900").expect("Could not bind socket");
    socket.join_multicast_v4(&Ipv4Addr::new(239, 255, 255, 250), &Ipv4Addr::new(0, 0, 0, 0))
        .expect("Could not join multicast group");

    let mut buffer = [0; 1024];
    let mut devices = Vec::new();

    println!("Listening for senders...");

    // 监听 SSDP 消息 10 秒
    let start_time = std::time::Instant::now();
    while start_time.elapsed() < Duration::from_secs(10) {
        if let Ok((size, _)) = socket.recv_from(&mut buffer) {
            let message = String::from_utf8_lossy(&buffer[..size]);
            if message.contains("SERVER: localshare/1.0") {
                let device_name = extract_field(&message, "USN: uuid:");
                let location = extract_field(&message, "LOCATION: ");

                if !device_name.is_empty() && !location.is_empty() {
                    let device_info = (device_name.clone(), location.clone());
                    if !devices.contains(&device_info) {
                        devices.push(device_info.clone());
                        println!("Found device: {}, Location: {}", device_name, location);
                    }
                }
            }
        }
    }

    if devices.is_empty() {
        println!("No devices found.");
        return;
    }

    // 显示设备列表供用户选择
    println!("\nSelect a device to download from:");
    for (i, (device_name, location)) in devices.iter().enumerate() {
        println!("{}. Device: {}, Location: {}", i + 1, device_name, location);
    }

    // 获取用户输入
    let mut input = String::new();
    println!("Enter the number of the device: ");
    io::stdin().read_line(&mut input).expect("Failed to read input");

    if let Ok(choice) = input.trim().parse::<usize>() {
        if choice > 0 && choice <= devices.len() {
            let (device_name, location) = &devices[choice - 1];
            println!("Downloading from device: {}", device_name);

            // 下载文件
            download_file(location);
        } else {
            println!("Invalid choice.");
        }
    } else {
        println!("Invalid input.");
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
fn download_file(url: &str) {
    if let Ok(response) = get(url) {
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

        // 保存文件
        if let Ok(mut file) = std::fs::File::create(&file_name) {
            if let Ok(content) = response.bytes() {
                if file.write_all(&content).is_ok() {
                    println!("File downloaded successfully: {}", file_name);
                    return;
                }
            }
        }
    }
    eprintln!("Failed to download file from {}", url);
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
        receive_mode();
    }

    return;
}