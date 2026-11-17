/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * File:    netwatch.h
 * Purpose: Simple data structures and function declarations for all NetWatch modules.
 * ==============================================================================
 */

#ifndef NETWATCH_H
#define NETWATCH_H

#include <string>
#include <vector>
#include <map>

// Represents a single network socket / connection
struct Connection {
    std::string protocol;       // "TCP" or "UDP"
    std::string localAddress;   // e.g. "0.0.0.0:8080"
    std::string remoteAddress;  // e.g. "0.0.0.0:*"
    std::string state;          // "LISTEN", "ESTAB", etc.
    int localPort;              // 8080
    int pid;                    // Process ID (-1 if unknown)
    std::string processName;    // e.g. "python3" or "UNKNOWN"
    unsigned long inode;        // Socket inode from /proc
};

// -----------------------------------------------------------------------------
// Unix System Programming Helper (fork, execvp, pipe, dup2, waitpid)
// -----------------------------------------------------------------------------
std::string runCommand(const std::string& cmd, const std::vector<std::string>& args);

// -----------------------------------------------------------------------------
// Module 1 & Module 2: Network Connection & Listening Port Monitor
// -----------------------------------------------------------------------------
std::vector<Connection> getActiveConnections();
std::vector<Connection> getListeningPorts();
void printConnections(const std::vector<Connection>& conns);
void printListeningPorts(const std::vector<Connection>& ports);

// -----------------------------------------------------------------------------
// Module 3: Process-to-Port Mapper (/proc scanning & readlink)
// -----------------------------------------------------------------------------
std::vector<Connection> getProcessMappings();
void printProcessMappings(const std::vector<Connection>& mappings);

// -----------------------------------------------------------------------------
// Module 4: Real-Time Event Monitor
// -----------------------------------------------------------------------------
void runRealTimeMonitor(int intervalSeconds = 3, int maxCycles = 0);

// -----------------------------------------------------------------------------
// Module 5: Alert and Rule Engine
// -----------------------------------------------------------------------------
void loadRules(const std::string& filename = "config/rules.conf");
void viewRules();
void checkAndAlert(int port, const std::string& proto, const std::string& procName, int pid);

// -----------------------------------------------------------------------------
// Module 6: Logging and History
// -----------------------------------------------------------------------------
void logEvent(const std::string& message);
void viewLogs(int maxLines = 20);

// Helper for timestamp
std::string getTimestamp();

#endif // NETWATCH_H
