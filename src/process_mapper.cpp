/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    process_mapper.cpp
 * Purpose: Implements Module 3: Process-to-Port Mapper using the Linux /proc
 *          pseudo-filesystem and the POSIX readlink() system call.
 * ==============================================================================
 */

#include "process_mapper.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cctype>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>

std::string hexToIp(const std::string& hexIp) {
    if (hexIp.length() != 8) {
        return hexIp;
    }

    // In /proc/net/tcp, IPv4 addresses are stored as 8-character hex strings
    // in network byte order (little-endian on x86/ARM Linux systems).
    unsigned long val = 0;
    try {
        val = std::stoul(hexIp, nullptr, 16);
    } catch (...) {
        return "0.0.0.0";
    }

    // Extract each byte
    unsigned int b0 = (val & 0xFF);
    unsigned int b1 = ((val >> 8) & 0xFF);
    unsigned int b2 = ((val >> 16) & 0xFF);
    unsigned int b3 = ((val >> 24) & 0xFF);

    return std::to_string(b0) + "." + std::to_string(b1) + "." +
           std::to_string(b2) + "." + std::to_string(b3);
}

int hexToPort(const std::string& hexPort) {
    try {
        return std::stoi(hexPort, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

std::string tcpStateToString(int stateHex) {
    // Linux kernel TCP state definitions from <netinet/tcp.h>
    switch (stateHex) {
        case 0x01: return "ESTAB";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default:   return "UNKNOWN";
    }
}

std::string getProcessNameByPid(int pid) {
    // Read the binary command name from /proc/[pid]/comm
    std::string commPath = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream commFile(commPath);
    std::string name;

    if (commFile && (commFile >> name)) {
        return name;
    }

    return "UNKNOWN";
}

std::map<unsigned long, ProcessDetails> buildSocketInodeMap() {
    std::map<unsigned long, ProcessDetails> socketMap;

    // Step 1: Open the /proc directory
    DIR* procDir = opendir("/proc");
    if (!procDir) {
        perror("NetWatch Warning: Unable to open /proc directory");
        return socketMap;
    }

    struct dirent* procEntry = nullptr;

    // Step 2: Iterate over all entries in /proc
    while ((procEntry = readdir(procDir)) != nullptr) {
        // We only care about directories whose names are purely numeric (representing PIDs)
        std::string dName = procEntry->d_name;
        bool isPid = !dName.empty();
        for (char c : dName) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                isPid = false;
                break;
            }
        }

        if (!isPid) {
            continue;
        }

        int pid = 0;
        try {
            pid = std::stoi(dName);
        } catch (...) {
            continue;
        }

        // Get the process binary name
        std::string procName = getProcessNameByPid(pid);

        // Step 3: Inspect the file descriptors of this process in /proc/[PID]/fd/
        std::string fdDirPath = "/proc/" + dName + "/fd";
        DIR* fdDir = opendir(fdDirPath.c_str());

        // Note: opendir may fail (EACCES) if the process belongs to another user or root,
        // or (ENOENT) if the process terminated during iteration. We handle this gracefully.
        if (!fdDir) {
            continue;
        }

        struct dirent* fdEntry = nullptr;
        while ((fdEntry = readdir(fdDir)) != nullptr) {
            // Skip "." and ".."
            if (std::strcmp(fdEntry->d_name, ".") == 0 || std::strcmp(fdEntry->d_name, "..") == 0) {
                continue;
            }

            std::string linkPath = fdDirPath + "/" + fdEntry->d_name;
            char target[256];

            // Step 4: Use POSIX readlink() system call to inspect the file descriptor symlink
            ssize_t len = readlink(linkPath.c_str(), target, sizeof(target) - 1);
            if (len != -1) {
                target[len] = '\0';
                std::string targetStr(target);

                // Step 5: Check if the file descriptor points to a network socket
                // In Linux, socket file descriptors resolve to the format: "socket:[INODE]"
                if (targetStr.rfind("socket:[", 0) == 0) {
                    size_t closeBracket = targetStr.find(']');
                    if (closeBracket != std::string::npos) {
                        std::string inodeStr = targetStr.substr(8, closeBracket - 8);
                        try {
                            unsigned long inode = std::stoul(inodeStr);
                            ProcessDetails details;
                            details.pid = pid;
                            details.name = procName;
                            socketMap[inode] = details;
                        } catch (...) {
                            // Ignore malformed inode numbers
                        }
                    }
                }
            }
        }
        closedir(fdDir);
    }

    closedir(procDir);
    return socketMap;
}

static void parseProcNetFile(const std::string& filePath,
                             const std::string& protocol,
                             const std::map<unsigned long, ProcessDetails>& socketMap,
                             std::vector<ConnectionInfo>& results) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return; // File not accessible or IPv6 not supported on this kernel
    }

    std::string line;
    // Skip the header line
    // e.g. "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    if (!std::getline(file, line)) {
        return;
    }

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string sl, localAddrStr, remAddrStr, stStr;
        std::string txrx, trTm, retrnsmt, uid, timeout, inodeStr;

        if (!(iss >> sl >> localAddrStr >> remAddrStr >> stStr >> txrx >> trTm >> retrnsmt >> uid >> timeout >> inodeStr)) {
            continue;
        }

        // Split local_address into Hex IP and Hex Port
        size_t localColon = localAddrStr.find(':');
        if (localColon == std::string::npos) continue;
        std::string localHexIp = localAddrStr.substr(0, localColon);
        std::string localHexPort = localAddrStr.substr(localColon + 1);

        // Split rem_address into Hex IP and Hex Port
        size_t remColon = remAddrStr.find(':');
        if (remColon == std::string::npos) continue;
        std::string remHexIp = remAddrStr.substr(0, remColon);
        std::string remHexPort = remAddrStr.substr(remColon + 1);

        // Parse State
        int stateHex = 0;
        try {
            stateHex = std::stoi(stStr, nullptr, 16);
        } catch (...) {
            stateHex = 0;
        }

        // Parse Socket Inode
        unsigned long inode = 0;
        try {
            inode = std::stoul(inodeStr);
        } catch (...) {
            inode = 0;
        }

        ConnectionInfo conn;
        conn.protocol = protocol;
        conn.inode = inode;

        // Decode IP addresses and ports
        if (localHexIp.length() == 8) {
            conn.localIp = hexToIp(localHexIp);
        } else {
            conn.localIp = "IPv6"; // IPv6 format
        }
        conn.localPort = hexToPort(localHexPort);

        if (remHexIp.length() == 8) {
            conn.remoteIp = hexToIp(remHexIp);
        } else {
            conn.remoteIp = "*";
        }
        conn.remotePort = hexToPort(remHexPort);

        if (protocol == "UDP") {
            conn.state = (conn.remotePort == 0) ? "LISTEN(UDP)" : "ESTAB(UDP)";
        } else {
            conn.state = tcpStateToString(stateHex);
        }

        // Step 6: Correlate Socket Inode with the Process Map!
        auto it = socketMap.find(inode);
        if (it != socketMap.end()) {
            conn.pid = it->second.pid;
            conn.processName = it->second.name;
        } else {
            conn.pid = -1;
            conn.processName = "UNKNOWN";
        }

        results.push_back(conn);
    }
}

std::vector<ConnectionInfo> getProcessPortMappings() {
    // Step 1: Scan /proc/[PID]/fd to discover all socket:[INODE] references
    std::map<unsigned long, ProcessDetails> socketMap = buildSocketInodeMap();

    // Step 2: Read Linux kernel network socket tables
    std::vector<ConnectionInfo> mappings;
    parseProcNetFile("/proc/net/tcp", "TCP", socketMap, mappings);
    parseProcNetFile("/proc/net/udp", "UDP", socketMap, mappings);
    parseProcNetFile("/proc/net/tcp6", "TCP6", socketMap, mappings);
    parseProcNetFile("/proc/net/udp6", "UDP6", socketMap, mappings);

    // If any socket is still UNKNOWN because of permission restrictions on /proc/[PID]/fd,
    // we cross-check with Module 1 & 2's ss collector as an intelligent fallback.
    std::vector<ConnectionInfo> ssList = getListeningPorts();
    for (auto& conn : mappings) {
        if (conn.pid <= 0 || conn.processName == "UNKNOWN") {
            for (const auto& ssConn : ssList) {
                if (ssConn.localPort == conn.localPort && ssConn.pid > 0) {
                    conn.pid = ssConn.pid;
                    conn.processName = ssConn.processName;
                    break;
                }
            }
        }
    }

    return mappings;
}

void printProcessPortMapping(const std::vector<ConnectionInfo>& mappings) {
    std::cout << "\n========================================================================================\n";
    std::cout << "                         MODULE 3: PROCESS-TO-PORT MAPPER                               \n";
    std::cout << "                  Correlated via Linux /proc and socket inodes                          \n";
    std::cout << "========================================================================================\n";
    std::cout << std::left
              << std::setw(8)  << "PORT"
              << std::setw(8)  << "PROTO"
              << std::setw(22) << "LOCAL BIND"
              << std::setw(12) << "STATE"
              << std::setw(12) << "INODE"
              << std::setw(8)  << "PID"
              << "PROCESS" << "\n";
    std::cout << "----------------------------------------------------------------------------------------\n";

    if (mappings.empty()) {
        std::cout << "No sockets found in /proc/net at this moment.\n";
    } else {
        for (const auto& conn : mappings) {
            // Highlight listening ports and active sockets
            std::string pidStr = (conn.pid > 0) ? std::to_string(conn.pid) : "-";
            std::string inodeStr = (conn.inode > 0) ? std::to_string(conn.inode) : "-";

            std::cout << std::left
                      << std::setw(8)  << conn.localPort
                      << std::setw(8)  << conn.protocol
                      << std::setw(22) << conn.localIp
                      << std::setw(12) << conn.state
                      << std::setw(12) << inodeStr
                      << std::setw(8)  << pidStr
                      << conn.processName << "\n";
        }
    }
    std::cout << "----------------------------------------------------------------------------------------\n";
    std::cout << "Total Sockets Mapped: " << mappings.size() << "\n";
}
