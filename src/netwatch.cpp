/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * File:    netwatch.cpp
 * Purpose: Simplified, beginner-friendly implementation of all NetWatch modules.
 * ==============================================================================
 */

#include "netwatch.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

using namespace std;

// In-memory rules map: Port -> Description (e.g. 4444 -> "Metasploit_Default_Listener")
static map<int, string> g_rules;

// Global flag to stop real-time monitoring on Ctrl+C (SIGINT)
static volatile sig_atomic_t g_stopMonitoring = 0;

static void handleSigint(int) {
    g_stopMonitoring = 1;
}

// -----------------------------------------------------------------------------
// Helper: Get current timestamp string (YYYY-MM-DD HH:MM:SS)
// -----------------------------------------------------------------------------
string getTimestamp() {
    time_t now = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

// -----------------------------------------------------------------------------
// Unix Helper: Run a command using fork(), pipe(), dup2(), and execvp()
// -----------------------------------------------------------------------------
string runCommand(const string& cmd, const vector<string>& args) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe failed");
        return "";
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return "";
    }

    if (pid == 0) {
        // --- CHILD PROCESS ---
        close(pipefd[0]);               // Close read end
        dup2(pipefd[1], STDOUT_FILENO);  // Redirect stdout to pipe
        dup2(pipefd[1], STDERR_FILENO);  // Redirect stderr to pipe
        close(pipefd[1]);               // Close original write end

        // Prepare arguments for execvp
        vector<char*> c_argv;
        c_argv.push_back(const_cast<char*>(cmd.c_str()));
        for (const auto& a : args) {
            c_argv.push_back(const_cast<char*>(a.c_str()));
        }
        c_argv.push_back(nullptr);

        execvp(cmd.c_str(), c_argv.data());
        _exit(127); // Exit child if execvp fails
    }

    // --- PARENT PROCESS ---
    close(pipefd[1]); // MUST close write end so read() sees EOF

    string output = "";
    char buffer[2048];
    ssize_t bytesRead;
    while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    close(pipefd[0]);

    // Wait for child to exit to prevent zombie process
    int status;
    waitpid(pid, &status, 0);

    return output;
}

// -----------------------------------------------------------------------------
// Helper: Extract port number from an address string (e.g. "0.0.0.0:8080" -> 8080)
// -----------------------------------------------------------------------------
static int extractPort(const string& addr) {
    size_t pos = addr.rfind(':');
    if (pos == string::npos) return 0;
    string portStr = addr.substr(pos + 1);
    if (portStr == "*" || portStr.empty()) return 0;
    try {
        return stoi(portStr);
    } catch (...) {
        return 0;
    }
}

// -----------------------------------------------------------------------------
// Helper: Parse process name and PID from ss output (e.g. users:(("python3",pid=34,fd=3)))
// -----------------------------------------------------------------------------
static void extractProcessInfo(const string& text, int& pid, string& name) {
    pid = -1;
    name = "UNKNOWN";

    // Extract process name between quotes " "
    size_t q1 = text.find('"');
    if (q1 != string::npos) {
        size_t q2 = text.find('"', q1 + 1);
        if (q2 != string::npos) {
            name = text.substr(q1 + 1, q2 - q1 - 1);
        }
    }

    // Extract PID after "pid="
    size_t p = text.find("pid=");
    if (p != string::npos) {
        try {
            pid = stoi(text.substr(p + 4));
        } catch (...) {
            pid = -1;
        }
    }
}

// -----------------------------------------------------------------------------
// Module 1: Get Active Network Connections
// -----------------------------------------------------------------------------
vector<Connection> getActiveConnections() {
    vector<Connection> conns;
    string raw = runCommand("ss", {"-tunapn"});

    stringstream ss(raw);
    string line;
    while (getline(ss, line)) {
        // Skip header lines or warning lines
        if (line.empty() || line.find("Netid") != string::npos || line.find("Failed") != string::npos) {
            continue;
        }

        stringstream lineStream(line);
        string netid, state, recvQ, sendQ, localAddr, peerAddr;
        if (!(lineStream >> netid >> state >> recvQ >> sendQ >> localAddr >> peerAddr)) {
            continue;
        }

        // Convert protocol to uppercase
        string proto = netid;
        for (char& c : proto) c = toupper(c);

        Connection c;
        c.protocol = proto;
        c.state = state;
        c.localAddress = localAddr;
        c.remoteAddress = peerAddr;
        c.localPort = extractPort(localAddr);
        c.inode = 0;

        // Parse remaining text for process info
        string rest;
        getline(lineStream, rest);
        extractProcessInfo(rest, c.pid, c.processName);

        conns.push_back(c);
    }
    return conns;
}

// -----------------------------------------------------------------------------
// Module 2: Get Listening Ports
// -----------------------------------------------------------------------------
vector<Connection> getListeningPorts() {
    vector<Connection> all = getActiveConnections();
    vector<Connection> listeners;

    for (const auto& c : all) {
        // TCP is listening when state is LISTEN
        // UDP is listening when remote address is wildcard (*:*)
        bool isListen = (c.state == "LISTEN") ||
                        (c.protocol == "UDP" && (c.remoteAddress.find("*") != string::npos || c.remoteAddress.find(":0") != string::npos));
        if (isListen) {
            listeners.push_back(c);
        }
    }
    return listeners;
}

void printConnections(const vector<Connection>& conns) {
    cout << "\n========================================================================================\n";
    cout << "                         MODULE 1: ACTIVE NETWORK CONNECTIONS                           \n";
    cout << "========================================================================================\n";
    cout << left << setw(6) << "PROTO"
         << setw(24) << "LOCAL ADDRESS"
         << setw(24) << "REMOTE ADDRESS"
         << setw(12) << "STATE"
         << setw(8)  << "PID"
         << "PROCESS\n";
    cout << "----------------------------------------------------------------------------------------\n";

    if (conns.empty()) {
        cout << "No active network connections found at this moment.\n";
    } else {
        for (const auto& c : conns) {
            string pidStr = (c.pid > 0) ? to_string(c.pid) : "-";
            cout << left << setw(6) << c.protocol
                 << setw(24) << c.localAddress
                 << setw(24) << c.remoteAddress
                 << setw(12) << c.state
                 << setw(8)  << pidStr
                 << c.processName << "\n";
        }
    }
    cout << "----------------------------------------------------------------------------------------\n";
    cout << "Total Active Sockets: " << conns.size() << "\n";
}

void printListeningPorts(const vector<Connection>& ports) {
    cout << "\n========================================================================================\n";
    cout << "                         MODULE 2: LISTENING PORT MONITOR                               \n";
    cout << "========================================================================================\n";
    cout << left << setw(8) << "PORT"
         << setw(8) << "PROTO"
         << setw(24) << "BIND ADDRESS"
         << setw(8)  << "PID"
         << "PROCESS\n";
    cout << "----------------------------------------------------------------------------------------\n";

    if (ports.empty()) {
        cout << "No listening ports detected at this moment.\n";
    } else {
        for (const auto& p : ports) {
            string pidStr = (p.pid > 0) ? to_string(p.pid) : "-";
            cout << left << setw(8) << p.localPort
                 << setw(8) << p.protocol
                 << setw(24) << p.localAddress
                 << setw(8)  << pidStr
                 << p.processName << "\n";
        }
    }
    cout << "----------------------------------------------------------------------------------------\n";
    cout << "Total Listening Services: " << ports.size() << "\n";
}

// -----------------------------------------------------------------------------
// Module 3: Process-to-Port Mapper using Linux /proc filesystem
// -----------------------------------------------------------------------------
// Step 1: Scan /proc/[PID]/fd/* to find symlinks like "socket:[190576]" -> map inode to PID & Name
static map<unsigned long, pair<int, string>> buildSocketInodeMap() {
    map<unsigned long, pair<int, string>> socketMap;

    DIR* procDir = opendir("/proc");
    if (!procDir) return socketMap;

    struct dirent* entry;
    while ((entry = readdir(procDir)) != nullptr) {
        // Check if folder name is purely numeric (a PID)
        string dname = entry->d_name;
        bool isNum = !dname.empty();
        for (char c : dname) {
            if (!isdigit(c)) { isNum = false; break; }
        }
        if (!isNum) continue;

        int pid = stoi(dname);

        // Read process name from /proc/[pid]/comm
        string procName = "UNKNOWN";
        ifstream commFile("/proc/" + dname + "/comm");
        if (commFile) { commFile >> procName; }

        // Scan file descriptors in /proc/[pid]/fd
        string fdPath = "/proc/" + dname + "/fd";
        DIR* fdDir = opendir(fdPath.c_str());
        if (!fdDir) continue; // Skip if permission denied

        struct dirent* fdEntry;
        while ((fdEntry = readdir(fdDir)) != nullptr) {
            string linkPath = fdPath + "/" + fdEntry->d_name;
            char target[256];
            ssize_t len = readlink(linkPath.c_str(), target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                string t = target;
                // Target looks like: "socket:[190576]"
                if (t.find("socket:[") == 0) {
                    size_t end = t.find(']');
                    if (end != string::npos) {
                        try {
                            unsigned long inode = stoul(t.substr(8, end - 8));
                            socketMap[inode] = {pid, procName};
                        } catch (...) {}
                    }
                }
            }
        }
        closedir(fdDir);
    }
    closedir(procDir);
    return socketMap;
}

vector<Connection> getProcessMappings() {
    // 1. Build map of: Socket Inode -> {PID, Process Name}
    map<unsigned long, pair<int, string>> socketMap = buildSocketInodeMap();

    // 2. Read /proc/net/tcp to get open sockets and their inodes
    vector<Connection> mappings;
    ifstream netFile("/proc/net/tcp");
    if (!netFile) return mappings;

    string line;
    getline(netFile, line); // Skip header line

    while (getline(netFile, line)) {
        stringstream ss(line);
        string sl, localAddr, remAddr, st, txrx, trTm, retrn, uid, timeout, inodeStr;
        if (!(ss >> sl >> localAddr >> remAddr >> st >> txrx >> trTm >> retrn >> uid >> timeout >> inodeStr)) {
            continue;
        }

        // Port is in hex after colon (e.g. "0100007F:1F90" -> "1F90")
        size_t col = localAddr.find(':');
        if (col == string::npos) continue;
        string hexPort = localAddr.substr(col + 1);

        int port = 0;
        try { port = stoi(hexPort, nullptr, 16); } catch (...) { port = 0; }

        unsigned long inode = 0;
        try { inode = stoul(inodeStr); } catch (...) { inode = 0; }

        Connection c;
        c.protocol = "TCP";
        c.localPort = port;
        c.localAddress = "0.0.0.0:" + to_string(port);
        c.state = (st == "0A") ? "LISTEN" : "ESTAB";
        c.inode = inode;
        c.pid = -1;
        c.processName = "UNKNOWN";

        // Match inode with our /proc scan
        if (socketMap.count(inode)) {
            c.pid = socketMap[inode].first;
            c.processName = socketMap[inode].second;
        }

        mappings.push_back(c);
    }

    // Also match with listening ports from ss as fallback
    vector<Connection> listeners = getListeningPorts();
    for (auto& m : mappings) {
        if (m.pid <= 0) {
            for (const auto& l : listeners) {
                if (l.localPort == m.localPort && l.pid > 0) {
                    m.pid = l.pid;
                    m.processName = l.processName;
                    break;
                }
            }
        }
    }

    return mappings;
}

void printProcessMappings(const vector<Connection>& mappings) {
    cout << "\n========================================================================================\n";
    cout << "                         MODULE 3: PROCESS-TO-PORT MAPPER                               \n";
    cout << "                  Correlated via Linux /proc and socket inodes                          \n";
    cout << "========================================================================================\n";
    cout << left << setw(8)  << "PORT"
         << setw(8)  << "PROTO"
         << setw(24) << "LOCAL BIND"
         << setw(12) << "STATE"
         << setw(12) << "INODE"
         << setw(8)  << "PID"
         << "PROCESS\n";
    cout << "----------------------------------------------------------------------------------------\n";

    if (mappings.empty()) {
        cout << "No sockets found in /proc/net/tcp at this moment.\n";
    } else {
        for (const auto& m : mappings) {
            string pidStr = (m.pid > 0) ? to_string(m.pid) : "-";
            string inodeStr = (m.inode > 0) ? to_string(m.inode) : "-";
            cout << left << setw(8)  << m.localPort
                 << setw(8)  << m.protocol
                 << setw(24) << m.localAddress
                 << setw(12) << m.state
                 << setw(12) << inodeStr
                 << setw(8)  << pidStr
                 << m.processName << "\n";
        }
    }
    cout << "----------------------------------------------------------------------------------------\n";
    cout << "Total Sockets Mapped: " << mappings.size() << "\n";
}

// -----------------------------------------------------------------------------
// Module 5: Rules & Alert Engine
// -----------------------------------------------------------------------------
void loadRules(const string& filename) {
    g_rules.clear();
    ifstream f(filename);
    if (!f.is_open()) {
        // Default fallback rules
        g_rules[4444] = "Metasploit_Default_Listener";
        g_rules[1337] = "Common_Backdoor_Port";
        g_rules[6667] = "IRC_Botnet_Channel";
        g_rules[8888] = "Suspicious_High_Port_Service";
        g_rules[9999] = "Suspicious_Remote_Access";
        return;
    }

    string line;
    while (getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        stringstream ss(line);
        string tag, desc;
        int port;
        // Format: PORT <port> <desc>
        if (ss >> tag >> port >> desc) {
            if (tag == "PORT" && port > 0 && port <= 65535) {
                g_rules[port] = desc;
            }
        }
    }
}

void viewRules() {
    cout << "\n========================================================================================\n";
    cout << "                     MODULE 5: SUSPICIOUS PORT RULES CONFIGURATION                      \n";
    cout << "Source: config/rules.conf\n";
    cout << "========================================================================================\n";
    cout << left << setw(10) << "PORT" << "DESCRIPTION\n";
    cout << "----------------------------------------------------------------------------------------\n";

    if (g_rules.empty()) loadRules();

    for (const auto& pair : g_rules) {
        cout << left << setw(10) << pair.first << pair.second << "\n";
    }
    cout << "----------------------------------------------------------------------------------------\n";
    cout << "Total Configured Rules: " << g_rules.size() << "\n";
}

void checkAndAlert(int port, const string& proto, const string& procName, int pid) {
    string ts = getTimestamp();
    string pidStr = (pid > 0) ? to_string(pid) : "UNKNOWN";

    // 1. Alert for any newly opened port
    string eventMsg = "[" + ts + "] [EVENT: NEW LISTENER] New listening port detected: " +
                      to_string(port) + " (" + proto + ") by process: " + procName + " (PID: " + pidStr + ")";
    cout << "\033[1;33m" << eventMsg << "\033[0m\n";
    logEvent(eventMsg);

    // 2. Check if the port is in our suspicious rules list
    if (g_rules.count(port)) {
        string alertMsg = "[" + ts + "] [ALERT: SUSPICIOUS] Unexpected local port detected: " +
                          to_string(port) + " (" + g_rules[port] + ") | Protocol: " + proto +
                          " | Process: " + procName + " (PID " + pidStr + ")";
        cout << "\033[1;31m" << alertMsg << "\033[0m\n";
        logEvent(alertMsg);
    }
}

// -----------------------------------------------------------------------------
// Module 6: Persistent Logging
// -----------------------------------------------------------------------------
void logEvent(const string& message) {
    // Ensure logs/ directory exists
    mkdir("logs", 0755);

    // Append to logs/netwatch.log
    ofstream f("logs/netwatch.log", ios::app);
    if (f.is_open()) {
        f << message << "\n";
    }
}

void viewLogs(int maxLines) {
    cout << "\n========================================================================================\n";
    cout << "                         MODULE 6: HISTORICAL AUDIT LOGS                                \n";
    cout << "Source: logs/netwatch.log\n";
    cout << "========================================================================================\n";

    ifstream f("logs/netwatch.log");
    if (!f.is_open()) {
        cout << "[!] No log entries found yet. Run monitoring to record events.\n";
        cout << "========================================================================================\n";
        return;
    }

    vector<string> lines;
    string line;
    while (getline(f, line)) {
        if (!line.empty()) lines.push_back(line);
    }

    if (lines.empty()) {
        cout << "Log file is currently empty.\n";
    } else {
        size_t start = (maxLines > 0 && lines.size() > (size_t)maxLines) ? lines.size() - maxLines : 0;
        for (size_t i = start; i < lines.size(); ++i) {
            cout << lines[i] << "\n";
        }
    }
    cout << "========================================================================================\n";
}

// -----------------------------------------------------------------------------
// Module 4: Real-Time Event Monitor
// -----------------------------------------------------------------------------
void runRealTimeMonitor(int intervalSeconds, int maxCycles) {
    // Register signal handler for Ctrl+C
    signal(SIGINT, handleSigint);
    g_stopMonitoring = 0;

    if (g_rules.empty()) loadRules();

    cout << "\n========================================================================================\n";
    cout << "                         MODULE 4: REAL-TIME EVENT MONITOR                              \n";
    cout << "========================================================================================\n";
    cout << "[*] Monitoring interval : " << intervalSeconds << " second(s)\n";
    cout << "[*] Signal handling     : SIGINT (Ctrl+C) enabled for graceful exit\n";
    cout << "[*] Rules loaded from   : config/rules.conf (" << g_rules.size() << " suspicious ports registered)\n";
    cout << "[*] Logging destination : logs/netwatch.log\n";
    cout << "[*] Status              : Initializing baseline snapshot...\n";

    // Baseline snapshot
    vector<Connection> prevPorts = getListeningPorts();
    cout << "[+] Baseline established: " << prevPorts.size() << " listening service(s).\n";
    cout << "----------------------------------------------------------------------------------------\n";
    cout << "Monitoring active. (Press Ctrl+C at any time to return to menu)\n";
    cout << "----------------------------------------------------------------------------------------\n";

    int cycle = 0;
    while (!g_stopMonitoring) {
        // Sleep in 100ms slices for fast Ctrl+C response
        for (int i = 0; i < intervalSeconds * 10 && !g_stopMonitoring; ++i) {
            usleep(100000); // 100 milliseconds
        }
        if (g_stopMonitoring) break;

        cycle++;
        vector<Connection> currPorts = getListeningPorts();

        // 1. Detect newly opened ports (present in currPorts, but not in prevPorts)
        bool changeDetected = false;
        for (const auto& curr : currPorts) {
            bool found = false;
            for (const auto& prev : prevPorts) {
                if (curr.localPort == prev.localPort && curr.protocol == prev.protocol) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                changeDetected = true;
                checkAndAlert(curr.localPort, curr.protocol, curr.processName, curr.pid);
            }
        }

        // 2. Detect closed ports (present in prevPorts, but not in currPorts)
        for (const auto& prev : prevPorts) {
            bool found = false;
            for (const auto& curr : currPorts) {
                if (prev.localPort == curr.localPort && prev.protocol == curr.protocol) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                changeDetected = true;
                string closeMsg = "[" + getTimestamp() + "] [EVENT: PORT CLOSED] Listening port closed: " +
                                  to_string(prev.localPort) + " (" + prev.protocol + ")";
                cout << "\033[1;34m" << closeMsg << "\033[0m\n";
                logEvent(closeMsg);
            }
        }

        // Heartbeat if no changes
        if (!changeDetected) {
            cout << "[" << getTimestamp() << "] Scan cycle #" << cycle
                 << ": No network changes detected. (" << currPorts.size() << " listeners)\n";
        }

        prevPorts = currPorts;

        if (maxCycles > 0 && cycle >= maxCycles) {
            cout << "[*] Reached test limit of " << maxCycles << " scan cycles.\n";
            break;
        }
    }

    cout << "\n----------------------------------------------------------------------------------------\n";
    cout << "[+] Real-time monitoring stopped gracefully.\n";
    cout << "========================================================================================\n";
}
