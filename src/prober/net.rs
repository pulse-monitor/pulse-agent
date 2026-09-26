//! TCP 与 HTTP 探测。**都不需要任何特权。**

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// TCP `connect()` 计时。返回微秒；连不上或超时返回 `None`（计为丢包）。
///
/// 这是默认的探测方式：零特权，且几乎所有目标都有至少一个开着的端口。
pub async fn tcp_probe(host: &str, port: u16, timeout: Duration) -> Option<u32> {
    // IPv6 字面量（无论带不带括号）先规范成裸地址，再用 (host, port) 元组连接 ——
    // 标准库对元组会先按 IP 解析。直接 `format!("{host}:{port}")` 的话，
    // 裸 `::1` 会拼成 `::1:443` 切错，连接恒失败，被误判成丢包（N5）。
    let host = normalize_host(host);
    let t0 = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(stream)) => {
            // 立刻关掉，不占对端资源
            drop(stream);
            Some(elapsed_us(t0))
        }
        // 连接被拒 / DNS 失败 / 超时都算丢包，不是错误 ——
        // 探针不能因为目标不通就崩或刷错误日志
        _ => None,
    }
}

/// 把用户给的 host 规范成裸地址：去括号，主机名原样保留。
fn normalize_host(host: &str) -> String {
    let bare = host.trim_matches(|c| c == '[' || c == ']');
    // 是 IP 字面量就返回裸地址（连接时走 IP 解析分支）；
    // 主机名原样，交给 DNS
    if bare.parse::<std::net::IpAddr>().is_ok() {
        bare.to_string()
    } else {
        host.to_string()
    }
}

/// 切分 `host[:port]`，能处理 IPv6 字面量（带括号和不带括号的）。
///
/// 返回的主机是**去括号**的裸地址：`[::1]:8080` → `("::1", 8080)`，
/// 裸 `::1` → `("::1", 默认端口)`。调用方用 `(host, port)` 元组连接，
/// 标准库会先按 IP 解析，不需要括号。
pub(crate) fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    // 带括号的：[::1]:8080
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match after.strip_prefix(':') {
            Some(p) if p.chars().all(|c| c.is_ascii_digit()) => p.parse().ok()?,
            None => default_port, // "[::1]" 无端口
            _ => return None,      // "[::1]:" 尾随冒号、"[::1]:abc" 非法端口：拒绝
        };
        return Some((host.to_string(), port));
    }
    // 不带括号的 IPv6 字面量：冒号多于一个，整体当 host，不能 rsplit
    if authority.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some((authority.to_string(), default_port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            // 注意：p 为空（"example.com:"）时 parse 失败 → 整个拒绝，与原来一致
            Some((h.to_string(), p.parse().ok()?))
        }
        // 没有冒号、或冒号在开头（":8080" 这类）：整体当主机名，交给 DNS
        _ => Some((authority.to_string(), default_port)),
    }
}

/// HTTP 探测：连接 + 发一个 HEAD + 读状态行。
///
/// 刻意**不引入完整的 HTTP 客户端**：agent 要保持小，而这里只需要
/// 「服务是否在响应、状态码对不对」。`https://` 走已有的 rustls。
pub async fn http_probe(url: &str, expect: Option<u16>, timeout: Duration) -> Option<u32> {
    let (https, host, port, path) = parse_url(url)?;
    let t0 = Instant::now();

    // Host 头里的 IPv6 字面量按规范加括号；连接与 SNI 用裸地址
    let host_header = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.clone()
    };

    let result = tokio::time::timeout(timeout, async {
        let stream = TcpStream::connect((host.as_str(), port)).await.ok()?;
        let req = format!(
            "HEAD {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: pulse-agent\r\n\
             Connection: close\r\nAccept: */*\r\n\r\n"
        );
        let status = if https {
            let s = tls_connect(stream, &host).await?;
            exchange(s, &req).await?
        } else {
            exchange(stream, &req).await?
        };
        Some(status)
    })
    .await;

    match result {
        Ok(Some(status)) => match expect {
            // 指定了期望状态码就必须相符；没指定则只要有响应就算通
            Some(want) if status != want => None,
            _ => Some(elapsed_us(t0)),
        },
        _ => None,
    }
}

async fn tls_connect(
    stream: TcpStream,
    host: &str,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = host.to_string().try_into().ok()?;
    TlsConnector::from(std::sync::Arc::new(config))
        .connect(name, stream)
        .await
        .ok()
}

/// 发请求并解析状态行。只读首行 —— 我们不关心响应体。
async fn exchange<S>(mut s: S, req: &str) -> Option<u16>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    s.write_all(req.as_bytes()).await.ok()?;
    s.flush().await.ok()?;

    // 状态行不会超过这个长度；读太多是给恶意服务端的放大空间
    let mut buf = [0u8; 256];
    let n = s.read(&mut buf).await.ok()?;
    let head = std::str::from_utf8(&buf[..n]).ok()?;
    // "HTTP/1.1 200 OK"
    head.split_whitespace().nth(1)?.parse().ok()
}

/// 极简 URL 解析：返回 `(是否 https, 主机, 端口, 路径)`。
///
/// `pub(crate)`：探测任务的内网目标过滤（AM2）需要从 HTTP 任务的 URL 里取主机。
pub(crate) fn parse_url(url: &str) -> Option<(bool, String, u16, String)> {
    let (https, rest) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        // 没有 scheme 的一律拒绝：把 "evil.com" 当成相对路径去猜是危险的
        None => (false, url.strip_prefix("http://")?),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return None; // 不支持 userinfo —— 探测目标不该带凭据
    }
    // 主机部分返回去括号的裸地址，IPv6 由 split_host_port 处理（N5）
    let default_port = if https { 443 } else { 80 };
    let (host, port) = split_host_port(authority, default_port)?;
    Some((https, host, port, path.to_string()))
}

fn elapsed_us(t0: Instant) -> u32 {
    t0.elapsed().as_micros().min(u128::from(u32::MAX)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        assert_eq!(
            parse_url("https://example.com/health"),
            Some((true, "example.com".into(), 443, "/health".into()))
        );
        assert_eq!(
            parse_url("http://example.com"),
            Some((false, "example.com".into(), 80, "/".into()))
        );
        assert_eq!(
            parse_url("http://127.0.0.1:8080/a/b"),
            Some((false, "127.0.0.1".into(), 8080, "/a/b".into()))
        );
    }

    #[test]
    fn url_parsing_rejects_junk() {
        // 没有 scheme 的一律拒绝，避免把 "evil.com" 当成相对路径去猜
        for bad in ["", "example.com", "ftp://x", "https://", "//x"] {
            assert!(parse_url(bad).is_none(), "不该接受 {bad:?}");
        }
    }

    #[test]
    fn url_parsing_handles_ipv6_literals() {
        // N5：IPv6 字面量必须正确拆出裸地址 + 端口，不能 panic，更不能切错
        assert_eq!(
            parse_url("http://[::1]:8080/"),
            Some((false, "::1".into(), 8080, "/".into()))
        );
        assert_eq!(
            parse_url("https://[2001:db8::1]/x"),
            Some((true, "2001:db8::1".into(), 443, "/x".into()))
        );
        // 不带括号的裸地址：整体当 host
        assert_eq!(
            parse_url("http://::1/"),
            Some((false, "::1".into(), 80, "/".into()))
        );
        // 非法输入仍然拒绝
        for bad in ["http://[]/", "http://[::1]:/", "http://[::1]:abc/"] {
            assert!(parse_url(bad).is_none(), "不该接受 {bad:?}");
        }
    }

    #[test]
    fn split_host_port_cases() {
        assert_eq!(
            split_host_port("example.com:8080", 80),
            Some(("example.com".into(), 8080))
        );
        assert_eq!(
            split_host_port("example.com", 80),
            Some(("example.com".into(), 80))
        );
        assert_eq!(
            split_host_port("[::1]:8080", 80),
            Some(("::1".into(), 8080))
        );
        assert_eq!(split_host_port("[::1]", 80), Some(("::1".into(), 80)));
        assert_eq!(split_host_port("::1", 80), Some(("::1".into(), 80)));
        // 尾随冒号：与旧逻辑一致，拒绝
        assert_eq!(split_host_port("example.com:", 80), None);
        assert_eq!(split_host_port("[::1]:", 80), None);
    }

    #[test]
    fn normalize_host_strips_brackets() {
        assert_eq!(normalize_host("[::1]"), "::1");
        assert_eq!(normalize_host("::1"), "::1");
        assert_eq!(normalize_host("127.0.0.1"), "127.0.0.1");
        assert_eq!(normalize_host("example.com"), "example.com");
    }

    #[tokio::test]
    async fn tcp_probe_reaches_ipv6_literal() {
        // N5 回归：以前裸 ::1 会拼成 "::1:port" 导致连接恒失败（误判丢包）
        let l = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { while l.accept().await.is_ok() {} });

        let r = tcp_probe("::1", port, std::time::Duration::from_secs(2)).await;
        assert!(r.is_some(), "本机 IPv6 回环应当连得上");
        let r = tcp_probe("[::1]", port, std::time::Duration::from_secs(2)).await;
        assert!(r.is_some(), "带括号的 IPv6 字面量也应当连得上");
    }
}
