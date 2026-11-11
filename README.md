# NetWatch

**Watch your Linux network activity. Spot unexpected sockets fast.**

NetWatch is a lightweight terminal-based network and security monitor for Linux, built in C++17. It inspects active TCP/UDP connections, maps listening ports to running processes using `/proc`, detects new sockets in real time, and logs alerts locally with zero external dependencies.

## How it works

When you run NetWatch, it collects active socket information using `ss` through low-level Unix pipes (`fork`, `dup2`, `execvp`, `waitpid`) and traverses `/proc/net/tcp`, `/proc/net/udp`, and `/proc/[PID]/fd/` with `readlink()` to correlate socket inodes directly to PIDs and process names.

In real-time monitoring mode, NetWatch takes periodic network snapshots, compares them against the previous state to spot newly opened ports or connections, evaluates them against user-defined rules in `config/rules.conf`, and appends timestamped events to `logs/netwatch.log`.

## Features

- **Active Connection & Listening Port Monitor:** Displays TCP/UDP local and remote endpoints, socket states, PIDs, and process names.
- **Process-to-Port Mapper (`/proc`):** Resolves `socket:[INODE]` file descriptor symlinks directly to owning Linux processes.
- **Real-Time Event Monitor:** Detects newly opened/closed listening ports and new connections with graceful `Ctrl+C` (`SIGINT`) handling.
- **Configurable Alert Rules:** Flags unexpected or suspicious ports (such as `4444`, `1337`, `6667`) defined in `config/rules.conf`.
- **Persistent Audit Logs:** Automatically writes structured, append-only history to `logs/netwatch.log`.
- **Interactive Menu & CLI Flags:** Works interactively or via direct command-line flags.

## Build & Run

### Prerequisites

Install `g++`, `make`, and standard Linux network utilities if not already present:

```bash
# Fedora
sudo dnf install gcc-c++ make iproute procps-ng lsof

# Ubuntu / Debian
sudo apt update && sudo apt install g++ make iproute2 procps lsof
```

### Compile and Launch

```bash
make
./netwatch
```

### Command-Line Shortcuts

```bash
./netwatch -c             # Active network connections
./netwatch -l             # Listening ports
./netwatch -m             # /proc socket-to-PID mapping
./netwatch -r [sec]       # Real-time monitoring (default: 3s)
./netwatch -a             # View recorded security alerts
./netwatch -h [n]         # View last n historical log entries
./netwatch --help         # Show all options
```

## Testing

Run the automated test suite to verify compilation, `/proc` mapping, real-time alerts, and log generation:

```bash
make test
```

## Project Structure

```text
NetWatch/
├── config/               # Configurable suspicious port rules (rules.conf)
├── documentation/        # Project synopsis and final mini-project report
├── src/                  # C++17 source and header files
├── tests/                # End-to-end verification tests
├── .gitignore
├── Makefile
└── README.md
```

## Notes

- **Passive monitoring:** NetWatch never kills processes or modifies firewall rules.
- **Permissions:** Non-root users cannot read `/proc/[PID]/fd/` for processes owned by `root` or other users; those entries appear safely as `UNKNOWN` unless run with `sudo`.
