# npm Supply Chain Risk Gate

Scan the npm dependencies in `examples/demo-project` and compare how different detection tools respond to a malicious package.

---

## Mode 1: Run the Scanning Comparison Report

This is the main function of the project. It runs npm audit, OSV, npq, and GuardDog against every package in the demo project, then generates a side-by-side comparison report.

```bash
chmod +x run.sh clean.sh
./run.sh
```

The results will be written to `results/`:

```text
results/report.html     # Main report
results/report.csv      # Same result in CSV format
results/report.json     # Same result in JSON format
results/raw/            # Raw output from each tool
```

Clean the results:

```bash
./clean.sh
```

### Report Columns

| Column        | Description                                                                                                                                                                                                                                                               |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **npm audit** | Checks against known CVE data. Newly published malicious versions usually do not appear here.                                                                                                                                                                             |
| **OSV**       | Similar to npm audit, but queries the osv.dev vulnerability database.                                                                                                                                                                                                     |
| **npq**       | Checks package metadata, including expired domains, package age, missing provenance, and other supply chain risk signals.                                                                                                                                                 |
| **GuardDog**  | Datadog’s Semgrep-based behavior rules. It scans package source code for suspicious behavior patterns, such as environment variable serialization, reading and exfiltrating sensitive data, and abuse of install scripts. This is the core detection column of this demo. |

> Note: An earlier version included an OpenSSF dynamic analysis column, which would execute `npm install` inside a gVisor sandbox and monitor syscalls. However, the sandbox could not run properly in the WSL2 environment, so it has been removed. This version uses GuardDog’s static behavior analysis as the core detection method.

---

## Mode 2: Observe the postinstall Exfiltration Behavior

This mode does not generate the scanning report. Instead, it actually allows the `postinstall` script of `demo-malicious-tool` to run once during installation, so that you can directly observe how it reads `.env` and attempts to send the data out.

The exfiltration target is `host.docker.internal:4444`, so you need to open a listener on **port 4444** to receive the payload. Two approaches are provided below.

### Option A: Use the Built-in Listener in the Script

`run-install-demo.sh` includes a built-in `nc -lk 4444` listener, so you can run it directly without opening another terminal:

```bash
chmod +x run-install-demo.sh
./run-install-demo.sh
```

The script will perform the following steps: remove the old `node_modules` directory → start an `nc` listener on port 4444 in the background → build the image → run the container with `MODE=install-demo` to trigger `postinstall` → stop the listener after the demo finishes.

One limitation is that `nc` does not return a complete HTTP response, so the log may show a line like `exfil failed: socket hang up`. This is expected. The data has already reached the listener; `nc` simply did not reply with HTTP 200.

### Option B: Use a Python Listener in Another Terminal

This option gives the best demonstration result. It returns a proper HTTP 200 response, avoids the `socket hang up` message, and prints the received JSON payload clearly. This requires two terminals.

**Step 1 — Disable the built-in `nc` listener in `run-install-demo.sh`** to avoid competing for the same port. Comment out or remove the following lines:

```bash
# echo "[2/4] Starting exfil listener on port 4444..."
# nc -lk 4444 &
# NC_PID=$!
...
# kill $NC_PID 2>/dev/null || true
```

**Step 2 — Terminal A: Start the Python listener before running the demo:**

```bash
# Make sure no old listener is still using port 4444
kill $(lsof -ti:4444) 2>/dev/null

python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 4444))
s.listen(1)
print('Listening on 4444...')
while True:
    c, a = s.accept()
    print(c.recv(65536).decode(errors='replace'))
    c.close()
"
```

Once you see `Listening on 4444...`, the listener is ready. Keep this terminal running.

**Step 3 — Terminal B: Run the install demo:**

```bash
chmod +x run-install-demo.sh
./run-install-demo.sh
```

**Step 4 — Return to Terminal A and check the result.** You should see an HTTP POST request containing the stolen data, for example:

```text
POST / HTTP/1.1
Content-Type: application/json
Host: host.docker.internal:4444
...
{"source":"demo-malicious-tool postinstall",
 "envFile":{"KEY":"yeah-i-find-your-key-token"},
 "systemEnv":{ ...entire environment variables... }}
```

`envFile` is the content read from `.env`, and `systemEnv` is the serialized environment variable object. **This is the key supply chain attack scenario: the user only runs an installation command, but sensitive data has already been sent to an external address.**

At the same time, Terminal B will print the execution process of `postinstall`, and the script will write `examples/demo-project/postinstall-demo-log.json` to record what it captured during this run.

> In Option B, because the Python listener returns a proper HTTP 200 response, the `socket hang up` message from Option A will not appear.

---

## Demo Package

`examples/demo-project` depends on an intentionally vulnerable demo package:

```json
"demo-malicious-tool": "github:OuChiaYun/demo-malicious-tool#main"
```

This package contains a `postinstall` script. During installation, it reads the target project’s `.env` file and the full environment variable object, then attempts to exfiltrate them. npm audit and OSV do not flag it because it has no CVE, but GuardDog’s behavior rules can detect it.

> Security notice: This package is only for controlled demonstration. The exfiltration target is fixed to a local listener and does not connect to any real external server. Only run it against your own demo repository. Do not execute it in production projects or other people’s projects.
