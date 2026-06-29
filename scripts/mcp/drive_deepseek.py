#!/usr/bin/env python3
"""Drive a rustynet MCP stdio server's tool directly — no client reconnect needed.

When you rebuild `bin/rustynet-mcp-<name>`, the Claude Code client keeps the OLD
server process (it holds its exec-time image and caches the tool list), so new
tools won't appear in-session until you `/mcp` reconnect. This bypasses that: it
spawns the freshly-built binary, does the JSON-RPC handshake, calls one tool, and
(for the async deepseek live-lab tools) auto-polls `deepseek_live_lab_result`
until the report lands. So the latest tools are always reachable with one command.

Usage:
  scripts/mcp/drive_deepseek.py --tool deepseek_lab_run \
      --args '{"area":"macOS relay","macos":true}'
  scripts/mcp/drive_deepseek.py --tool deepseek_live_lab \
      --args '{"target":"x","failure_context":"...","max_steps":8}'
  scripts/mcp/drive_deepseek.py --bin bin/rustynet-mcp-deepseek --tool deepseek_read \
      --args '{"prompt":"...","model":"flash"}' --no-poll

Exit code 0 on a delivered result; non-zero on transport/timeout failure.
"""
import argparse, json, os, re, select, subprocess, sys, time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
JOB_RE = re.compile(r"\b(?:triage|labrun|docsync|recover)-\d+(?:-\d+)*\b")  # deepseek async job ids (incl. -millis-pid-seq)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="bin/rustynet-mcp-deepseek",
                    help="MCP server binary, repo-relative or absolute (default: bin/rustynet-mcp-deepseek)")
    ap.add_argument("--tool", required=True, help="tool name to call")
    ap.add_argument("--args", default="{}", help="tool arguments as a JSON object")
    ap.add_argument("--poll-interval", type=int, default=20)
    ap.add_argument("--poll-timeout", type=int, default=2400, help="max seconds to wait for an async report")
    ap.add_argument("--no-poll", action="store_true", help="don't auto-poll deepseek async jobs")
    a = ap.parse_args()

    binpath = a.bin if os.path.isabs(a.bin) else os.path.join(REPO, a.bin)
    if not os.path.exists(binpath):
        print(f"binary not found: {binpath}", file=sys.stderr)
        return 2
    try:
        tool_args = json.loads(a.args)
    except json.JSONDecodeError as e:
        print(f"--args is not valid JSON: {e}", file=sys.stderr)
        return 2

    p = subprocess.Popen([binpath], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def send(o):
        p.stdin.write(json.dumps(o) + "\n"); p.stdin.flush()

    def read_id(want, timeout):
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([p.stdout], [], [], max(0, end - time.time()))
            if not r:
                continue
            line = p.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                m = json.loads(line)
            except json.JSONDecodeError:
                continue
            if m.get("id") == want:
                return m
        return None

    def result_text(m):
        if m and "result" in m:
            try:
                return m["result"]["content"][0]["text"]
            except (KeyError, IndexError, TypeError):
                return json.dumps(m["result"])
        return json.dumps(m.get("error") if m else {"error": "no/!malformed response"})

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "drive_deepseek", "version": "0"}}})
        if read_id(1, 30) is None:
            print("server did not answer initialize", file=sys.stderr); return 3
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": a.tool, "arguments": tool_args}})
        m = read_id(2, 180)
        text = result_text(m)

        job = JOB_RE.search(text or "") if text else None
        if a.no_poll:
            if job:
                # This direct stdio driver owns the MCP server process. Async
                # tools spawn a worker thread after returning the job id; exiting
                # immediately can kill the server before the worker records the
                # detached orchestrator pid. Hold the process briefly so --no-poll
                # stays safe for labrun/recover/docsync/triage launches.
                time.sleep(3)
            print(text)
            return 0

        if not job:
            print(text)
            return 0

        jid = job.group(0)
        print(f"[async] {a.tool} -> job {jid}; polling deepseek_live_lab_result...", file=sys.stderr)
        t0 = time.time()
        pid = 10
        while time.time() - t0 < a.poll_timeout:
            time.sleep(a.poll_interval)
            pid += 1
            send({"jsonrpc": "2.0", "id": pid, "method": "tools/call",
                  "params": {"name": "deepseek_live_lab_result", "arguments": {"job_id": jid}}})
            r = result_text(read_id(pid, 30))
            if "still running" in r:
                print(f"  [{time.time()-t0:.0f}s] {r.strip()[:80]}", file=sys.stderr)
                continue
            print(r)
            return 0
        print(f"timed out after {a.poll_timeout}s waiting for {jid}", file=sys.stderr)
        return 4
    finally:
        try:
            p.stdin.close()
        except Exception:
            pass
        p.kill()


if __name__ == "__main__":
    sys.exit(main())
