/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    network_monitor.cpp
 * Purpose: Implements Module 1 (Active Connection Monitor) and Module 2
 *          (Listening Port Monitor) using the Unix command execution helper.
 * ==============================================================================
 */

#include "network_monitor.h"
#include "command_runner.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>

void parseEndpoint(const std::string& endpoint, std::string& ip, int& port) {
    ip = "";
    port = 0;

    if (endpoint.empty()) {
        ip = "*";
        return;
    }

    // In ss output, an endpoint is formatted as IP:PORT (e.g., "127.0.0.1:8080" or "[::]:22")
    // We locate the last colon to separate IP from Port, handling IPv6 brackets properly.
    size_t colonPos = endpoint.rfind(':');
    if (colonPos == std::string::npos) {
        ip = endpoint;
        port = 0;
        return;
    }

    ip = endpoint.substr(0, colonPos);
    std::string portStr = endpoint.substr(colonPos + 1);

    if (portStr == "*" || portStr.empty()) {
        port = 0;
    } else {
        try {
            port = std::stoi(portStr);
        } catch (...) {
            port = 0;
        }
    }
}

void parseProcessField(const std::string& field, int& pid, std::string& processName) {
    pid = -1;
    processName = "UNKNOWN";

    if (field.empty()) {
        return;
    }

    // Typical ss output format: users:(("python3",pid=34,fd=3))
    // Step 1: Extract process binary name enclosed within quotation marks
    size_t q1 = field.find('"');
    if (q1 != std::string::npos) {
        size_t q2 = field.find('"', q1 + 1);
        if (q2 != std::string::npos && q2 > q1) {
            processName = field.substr(q1 + 1, q2 - q1 - 1);
        }
    }

    // Step 2: Extract Process ID following "pid="
    size_t pPos = field.find("pid=");
    if (pPos != std::string::npos) {
        size_t start = pPos + 4; // Length of "pid=" is 4
        size_t end = start;
        while (end < field.size() && std::isdigit(static_cast<unsigned char>(field[end]))) {
            end++;
        }
        if (end > start) {
            try {
                pid = std::stoi(field.substr(start, end - start));
            } catch (...) {
                pid = -1;
            }
        }
    }
}

std::vector<ConnectionInfo> parseSsOutput(const std::string& rawOutput, bool listeningOnly) {
    std::vector<ConnectionInfo> connections;
    std::istringstream stream(rawOutput);
    std::string line;

    while (std::getline(stream, line)) {
        // Skip empty lines, headers, and system warning messages
        if (line.empty() || line.find("Netid") != std::string::npos ||
            line.find("RTNETLINK") != std::string::npos ||
            line.find("Failed to") != std::string::npos) {
            continue;
        }

        std::istringstream lineStream(line);
        std::string netid, state, recvQ, sendQ, localEp, peerEp;

        if (!(lineStream >> netid >> state >> recvQ >> sendQ >> localEp >> peerEp)) {
            continue; // Line does not have the required columns
        }

        // Convert protocol to uppercase (e.g., "tcp" -> "TCP", "udp" -> "UDP")
        std::string protocol = netid;
        std::transform(protocol.begin(), protocol.end(), protocol.begin(), ::toupper);

        // Standardize state
        std::string upperState = state;
        std::transform(upperState.begin(), upperState.end(), upperState.begin(), ::toupper);

        // Check if socket is in listening mode:
        // - For TCP: state is LISTEN
        // - For UDP: peer address is wildcard (*:*) or state is UNCONN with no remote port
        bool isListening = (upperState == "LISTEN");
        if (protocol == "UDP") {
            if (peerEp.find("*") != std::string::npos || peerEp.empty() || peerEp == "*:*") {
                isListening = true;
                if (upperState == "UNCONN") {
                    upperState = "LISTEN(UDP)";
                }
            }
        }

        // If listeningOnly is requested, filter out non-listening sockets
        if (listeningOnly && !isListening) {
            continue;
        }

        ConnectionInfo conn;
        conn.protocol = protocol;
        conn.state = upperState;
        conn.inode = 0;

        parseEndpoint(localEp, conn.localIp, conn.localPort);
        parseEndpoint(peerEp, conn.remoteIp, conn.remotePort);

        // Extract remaining text on the line which contains process info
        std::string remaining;
        std::getline(lineStream, remaining);
        parseProcessField(remaining, conn.pid, conn.processName);

        connections.push_back(conn);
    }

    return connections;
}

std::vector<ConnectionInfo> getActiveConnections() {
    std::string rawOutput;
    // Execute: ss -tunapn (TCP, UDP, numeric addresses, all sockets, show processes)
    std::vector<std::string> args = {"ss", "-tunapn"};
    runCommand(args, rawOutput);

    // If ss failed or returned empty (rare), try without process flags
    if (rawOutput.empty()) {
        runCommand({"ss", "-tunan"}, rawOutput);
    }

    return parseSsOutput(rawOutput, false);
}

std::vector<ConnectionInfo> getListeningPorts() {
    std::string rawOutput;
    // Execute: ss -tulnp (TCP, UDP, listening only, numeric addresses, show processes)
    std::vector<std::string> args = {"ss", "-tulnpn"};
    runCommand(args, rawOutput);

    if (rawOutput.empty()) {
        runCommand({"ss", "-tuln"}, rawOutput);
    }

    return parseSsOutput(rawOutput, true);
}

void printActiveConnections(const std::vector<ConnectionInfo>& connections) {
    std::cout << "\n========================================================================================\n";
    std::cout << "                         MODULE 1: ACTIVE NETWORK CONNECTIONS                           \n";
    std::cout << "========================================================================================\n";
    std::cout << std::left
              << std::setw(6)  << "PROTO"
              << std::setw(23) << "LOCAL ADDRESS"
              << std::setw(23) << "REMOTE ADDRESS"
              << std::setw(14) << "STATE"
              << std::setw(8)  << "PID"
              << "PROCESS" << "\n";
    std::cout << "----------------------------------------------------------------------------------------\n";

    if (connections.empty()) {
        std::cout << "No active network connections found at this moment.\n";
    } else {
        for (const auto& conn : connections) {
            std::string localAddr = conn.localIp + ":" + std::to_string(conn.localPort);
            std::string remoteAddr = (conn.remotePort == 0 && conn.remoteIp == "*") 
                                     ? "*:*" 
                                     : (conn.remoteIp + ":" + std::to_string(conn.remotePort));

            std::string pidStr = (conn.pid > 0) ? std::to_string(conn.pid) : "-";

            std::cout << std::left
                      << std::setw(6)  << conn.protocol
                      << std::setw(23) << localAddr
                      << std::setw(23) << remoteAddr
                      << std::setw(14) << conn.state
                      << std::setw(8)  << pidStr
                      << conn.processName << "\n";
        }
    }
    std::cout << "----------------------------------------------------------------------------------------\n";
    std::cout << "Total Active Sockets/Connections: " << connections.size() << "\n";
}

void printListeningPorts(const std::vector<ConnectionInfo>& listeningPorts) {
    std::cout << "\n========================================================================================\n";
    std::cout << "                         MODULE 2: LISTENING PORT MONITOR                               \n";
    std::cout << "========================================================================================\n";
    std::cout << std::left
              << std::setw(8)  << "PORT"
              << std::setw(10) << "PROTO"
              << std::setw(24) << "BIND ADDRESS"
              << std::setw(8)  << "PID"
              << "PROCESS" << "\n";
    std::cout << "----------------------------------------------------------------------------------------\n";

    if (listeningPorts.empty()) {
        std::cout << "No listening ports detected at this moment.\n";
    } else {
        for (const auto& conn : listeningPorts) {
            std::string pidStr = (conn.pid > 0) ? std::to_string(conn.pid) : "-";
            std::cout << std::left
                      << std::setw(8)  << conn.localPort
                      << std::setw(10) << conn.protocol
                      << std::setw(24) << conn.localIp
                      << std::setw(8)  << pidStr
                      << conn.processName << "\n";
        }
    }
    std::cout << "----------------------------------------------------------------------------------------\n";
    std::cout << "Total Listening Services: " << listeningPorts.size() << "\n";
}
