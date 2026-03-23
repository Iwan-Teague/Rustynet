use std::env;
use std::net::TcpListener;
use std::thread;
use std::io::Write;

use rustynetd::daemon::StateFetcher;
use rustynetd::daemon::DaemonConfig;

#[test]
fn fetcher_skips_when_unconfigured() {
    // Ensure env unset
    env::remove_var("RUSTYNET_TRUST_URL");
    let cfg = DaemonConfig::default();
    let fetcher = StateFetcher::new_from_daemon(&cfg);
    let res = fetcher.fetch_trust();
    assert!(res.is_ok());
}

#[test]
fn fetcher_network_unreachable_skips() {
    // Set to localhost port unlikely to be open
    env::set_var("RUSTYNET_TRUST_URL", "http://127.0.0.1:9/trust");
    let cfg = DaemonConfig::default();
    let fetcher = StateFetcher::new_from_daemon(&cfg);
    let res = fetcher.fetch_trust();
    // network unreachable should be treated as skipped (Ok)
    assert!(res.is_ok());
}

#[test]
fn fetcher_bad_bundle_returns_error() {
    // Start a tiny TCP server that returns an HTTP response with a body that is not a valid bundle
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let server_thread = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    let url = format!("http://{}/trust", addr);
    env::set_var("RUSTYNET_TRUST_URL", url);
    let cfg = DaemonConfig::default();
    let fetcher = StateFetcher::new_from_daemon(&cfg);
    let res = fetcher.fetch_trust();
    assert!(res.is_err());
    // cleanup
    let _ = server_thread.join();
}
