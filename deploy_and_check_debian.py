import paramiko
import os
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--cmd", help="Command to run on remote host", default="cd ~/rustynet && ~/.cargo/bin/cargo test --test state_fetcher")
args = parser.parse_args()
hostname = "192.168.18.51"
username = "debian"
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
