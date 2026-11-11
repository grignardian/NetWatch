/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    network_monitor.h
 * Purpose: Declares data structures and functions for Module 1 (Active Network
 *          Connection Monitor) and Module 2 (Listening Port Monitor).
 * ==============================================================================
 */

#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include <string>
#include <vector>

// Structure representing a single network connection or socket
struct ConnectionInfo {
    std::string protocol;    // "TCP" or "UDP"
    std::string localIp;     // Local IP address (e.g., "127.0.0.1", "0.0.0.0", "::")
    int localPort;           // Local port number (e.g., 22, 8080)
    std::string remoteIp;    // Remote IP address (e.g., "192.168.1.10", "*")
    int remotePort;          // Remote port number (0 if wildcard/listening)
    std::string state;       // Connection state (e.g., "LISTEN", "ESTAB", "TIME-WAIT")
    int pid;                 // Owning Process ID (-1 if unmapped/unknown)
    std::string processName; // Owning Process binary name (e.g., "sshd", "python3")
    unsigned long inode;     // Socket inode number (used in Module 3)
};

/*
 * Splits an endpoint string (e.g., "127.0.0.1:8080" or "[::]:22") into IP and port.
 */
void parseEndpoint(const std::string& endpoint, std::string& ip, int& port);

/*
 * Extracts the process name and PID from an ss process string.
 * Example input: users:(("python3",pid=34,fd=3))
 */
void parseProcessField(const std::string& field, int& pid, std::string& processName);

/*
 * Parses the raw tabular output of the `ss` command into structured ConnectionInfo objects.
 * If listeningOnly is true, filters for listening sockets only.
 */
std::vector<ConnectionInfo> parseSsOutput(const std::string& rawOutput, bool listeningOnly);

/*
 * Module 1: Collects all active network connections using the Unix command execution helper.
 */
std::vector<ConnectionInfo> getActiveConnections();

/*
 * Module 2: Collects all currently listening TCP and UDP ports.
 */
std::vector<ConnectionInfo> getListeningPorts();

/*
 * Formatted table display for Module 1: Active Network Connections.
 */
void printActiveConnections(const std::vector<ConnectionInfo>& connections);

/*
 * Formatted table display for Module 2: Listening Ports.
 */
void printListeningPorts(const std::vector<ConnectionInfo>& listeningPorts);

#endif // NETWORK_MONITOR_H
