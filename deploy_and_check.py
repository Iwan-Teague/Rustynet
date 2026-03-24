import paramiko
import os
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--cmd", help="Command to run on remote host", default="cd ~/rustynet && ~/.cargo/bin/cargo test --test state_fetcher")
args = parser.parse_args()
hostname = "192.168.18.53"
username = "mint"
password = "tempo"
local_file = "crates/rustynetd/tests/state_fetcher.rs"
remote_file = "rustynet/crates/rustynetd/tests/state_fetcher.rs" # relative to home

print(f"Connecting to {hostname}...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    ssh.connect(hostname, username=username, password=password)
except Exception as e:
    print(f"Failed to connect: {e}")
    sys.exit(1)

print("Connection successful.")

sftp = ssh.open_sftp()

# Upload state_fetcher.rs
print(f"Uploading {local_file} to {remote_file}...")
sftp.put(local_file, remote_file)
print("Upload complete.")

# Upload daemon.rs
local_daemon = "crates/rustynetd/src/daemon.rs"
remote_daemon = "rustynet/crates/rustynetd/src/daemon.rs"
print(f"Uploading {local_daemon} to {remote_daemon}...")
sftp.put(local_daemon, remote_daemon)
print("Upload complete.")

# Upload Cargo.toml
local_cargo = "crates/rustynetd/Cargo.toml"
remote_cargo = "rustynet/crates/rustynetd/Cargo.toml"
print(f"Uploading {local_cargo} to {remote_cargo}...")
sftp.put(local_cargo, remote_cargo)
print("Upload complete.")

# Upload rustynet-cli/src/main.rs
local_cli = "crates/rustynet-cli/src/main.rs"
remote_cli = "rustynet/crates/rustynet-cli/src/main.rs"
print(f"Uploading {local_cli} to {remote_cli}...")
sftp.put(local_cli, remote_cli)
print("Upload complete.")

# Upload rustynet-cli/src/ops_ci_release_perf.rs
local_ops = "crates/rustynet-cli/src/ops_ci_release_perf.rs"
remote_ops = "rustynet/crates/rustynet-cli/src/ops_ci_release_perf.rs"
print(f"Uploading {local_ops} to {remote_ops}...")
sftp.put(local_ops, remote_ops)
print("Upload complete.")

# Upload crates/rustynet-cli/src/bin/check_fresh_install_os_matrix_readiness.rs
local_fresh = "crates/rustynet-cli/src/bin/check_fresh_install_os_matrix_readiness.rs"
remote_fresh = "rustynet/crates/rustynet-cli/src/bin/check_fresh_install_os_matrix_readiness.rs"
print(f"Uploading {local_fresh} to {remote_fresh}...")
sftp.put(local_fresh, remote_fresh)
print("Upload complete.")

# Upload crates/rustynetd/src/traversal.rs
local_traversal = "crates/rustynetd/src/traversal.rs"
remote_traversal = "rustynet/crates/rustynetd/src/traversal.rs"
print(f"Uploading {local_traversal} to {remote_traversal}...")
sftp.put(local_traversal, remote_traversal)
print("Upload complete.")

# Upload crates/rustynet-control/src/membership.rs
local_membership = "crates/rustynet-control/src/membership.rs"
remote_membership = "rustynet/crates/rustynet-control/src/membership.rs"
print(f"Uploading {local_membership} to {remote_membership}...")
sftp.put(local_membership, remote_membership)
print("Upload complete.")

# Upload crates/rustynet-relay/src/transport.rs
local_transport = "crates/rustynet-relay/src/transport.rs"
remote_transport = "rustynet/crates/rustynet-relay/src/transport.rs"
print(f"Uploading {local_transport} to {remote_transport}...")
sftp.put(local_transport, remote_transport)
print("Upload complete.")

# Upload crates/rustynetd/src/ipc.rs
local_ipc = "crates/rustynetd/src/ipc.rs"
remote_ipc = "rustynet/crates/rustynetd/src/ipc.rs"
print(f"Uploading {local_ipc} to {remote_ipc}...")
sftp.put(local_ipc, remote_ipc)
print("Upload complete.")

# Run remote command
command = args.cmd
print(f"Running command: {command}")
stdin, stdout, stderr = ssh.exec_command(command)

# Stream output
for line in stdout:
    print(line.strip())
for line in stderr:
    print(line.strip(), file=sys.stderr)

exit_status = stdout.channel.recv_exit_status()
print(f"Command finished with exit status {exit_status}")

ssh.close()
sys.exit(exit_status)
