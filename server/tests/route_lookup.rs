//! 集成测试（T-14）：Server 按 Route 的 listen 地址绑定 TCP 监听，客户端连接能匹配到 Route。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use tunnel_db::Db;
use tunnel_server::route::{RouteTable, ServerRoute};
use tunnel_server::tcp_proxy::TcpProxy;

const NODE_ID: &str = "11111111-1111-4111-8111-111111111111";
const ROUTE_ID: &str = "33333333-3333-4333-8333-333333333333";
const NOW: &str = "2026-08-27T00:00:00Z";

/// 建内存库 + 迁移 + 种入一个 node 与一条 TCP Route（listen 127.0.0.1:<port>）。
async fn seeded_db(listen_port: u16) -> Db {
    let db = Db::connect_memory().await.unwrap();
    db.migrate().await.unwrap();
    tunnel_db::sqlx::query(
        "INSERT INTO nodes (id, name, status, config_version, created_at, updated_at) \
         VALUES (?, ?, 'online', 7, ?, ?)",
    )
    .bind(NODE_ID)
    .bind("node-a")
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    tunnel_db::sqlx::query(
        "INSERT INTO routes \
         (id, name, node_id, type, enabled, listen_host, listen_port, target_host, target_port, \
          status, created_at, updated_at) \
         VALUES (?, ?, ?, 'tcp', 1, '127.0.0.1', ?, '192.168.1.100', 22, 'active', ?, ?)",
    )
    .bind(ROUTE_ID)
    .bind("ssh")
    .bind(NODE_ID)
    .bind(listen_port as i64)
    .bind(NOW)
    .bind(NOW)
    .execute(db.pool())
    .await
    .unwrap();
    db
}

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not met within timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_connect_matches_route() {
    let port = free_port().await;
    let db = seeded_db(port).await;

    let rows = db.list_routes().await.unwrap();
    assert_eq!(rows.len(), 1);

    let table = Arc::new(RouteTable::new());
    for row in rows {
        table.insert(ServerRoute::try_from(row).unwrap()).unwrap();
    }

    // listen → route 查找。
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let route = table.lookup(&addr).unwrap();
    assert_eq!(route.name, "ssh");
    assert_eq!(route.target_host, "192.168.1.100");
    assert_eq!(route.target_port, 22);

    // 绑定监听并启动接受循环。
    let proxy = TcpProxy::bind(table).await.unwrap();
    let addrs = proxy.local_addrs();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].0.to_string(), ROUTE_ID);
    assert_eq!(addrs[0].1.port(), port);
    proxy.run();

    // 客户端连接 → 匹配到该 Route（accepted 计数递增）。
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    wait_until(|| proxy.accepted_count() == 1).await;
    drop(stream);
}
