/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    process_mapper.h
 * Purpose: Declares functions and structures for Module 3: Process-to-Port Mapper.
 *          Maps network socket inodes from /proc/net/ to running Linux processes
 *          by inspecting /proc/[PID]/fd/ using readlink().
 * ==============================================================================
 */

#ifndef PROCESS_MAPPER_H
#define PROCESS_MAPPER_H

#include "network_monitor.h"
#include <string>
#include <vector>
#include <map>

// Structure to store basic process information
struct ProcessDetails {
    int pid;             // Process ID
    std::string name;    // Binary name from /proc/[pid]/comm
};

/*
 * Converts a hex-encoded IPv4 address from /proc/net/tcp (little-endian) to dotted-decimal.
 * Example: "0100007F" -> "127.0.0.1", "00000000" -> "0.0.0.0"
 */
std::string hexToIp(const std::string& hexIp);

/*
 * Converts a hex-encoded port string from /proc/net/tcp to an integer.
 * Example: "1F90" -> 8080, "0016" -> 22
 */
int hexToPort(const std::string& hexPort);

/*
 * Translates Linux kernel TCP state numbers (hex) into readable strings.
 * Example: 0x0A -> "LISTEN", 0x01 -> "ESTAB"
 */
std::string tcpStateToString(int stateHex);

/*
 * Reads the process binary name from /proc/[PID]/comm.
 * Returns "UNKNOWN" if permission is denied or process no longer exists.
 */
std::string getProcessNameByPid(int pid);

/*
 * Traverses /proc/[PID]/fd/ for all running processes using opendir(), readdir(),
 * and the POSIX readlink() system call to identify socket:[INODE] links.
 * Returns a map of: Socket Inode -> ProcessDetails (PID, Name)
 */
std::map<unsigned long, ProcessDetails> buildSocketInodeMap();

/*
 * Module 3 Core Function:
 * Reads /proc/net/tcp, /proc/net/udp (and IPv6 equivalents), extracts socket inodes,
 * and correlates them with the socket map generated from /proc/[PID]/fd/.
 */
std::vector<ConnectionInfo> getProcessPortMappings();

/*
 * Formatted table display for Module 3: Process-to-Port Mapping.
 */
void printProcessPortMapping(const std::vector<ConnectionInfo>& mappings);

#endif // PROCESS_MAPPER_H
