#[path = "live_cross_network_script_bin/mod.rs"]
mod live_cross_network_script_bin;

fn main() -> std::process::ExitCode {
    live_cross_network_script_bin::run(
        "scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh",
    )
}
