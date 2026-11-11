/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    alert_manager.cpp
 * Purpose: Implements Module 5: Alert and Rule Engine. Reads config/rules.conf
 *          and flags suspicious ports, new listeners, and new network processes.
 * ==============================================================================
 */

#include "alert_manager.h"

#include <iostream>
#include <fstream>
#include <sstream>

AlertManager::AlertManager(const std::string& configPath)
    : configFilePath(configPath) {
    if (!loadRules(configFilePath)) {
        // Fallback default rules if file is missing
        suspiciousPorts[4444] = "Metasploit_Default_Listener";
        suspiciousPorts[1337] = "Common_Backdoor_Port";
        suspiciousPorts[6667] = "IRC_Botnet_Channel";
        suspiciousPorts[8888] = "Suspicious_High_Port_Service";
        suspiciousPorts[9999] = "Suspicious_Remote_Access";
    }
}

bool AlertManager::loadRules(const std::string& configPath) {
    configFilePath = configPath;
    std::ifstream file(configFilePath);
    if (!file.is_open()) {
        return false;
    }

    suspiciousPorts.clear();
    std::string line;

    while (std::getline(file, line)) {
        // Skip empty lines and comment lines starting with '#'
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::istringstream iss(line);
        std::string tag, desc;
        int port = 0;

        // Expect format: PORT <number> <description>
        if (iss >> tag >> port >> desc) {
            if (tag == "PORT" && port > 0 && port <= 65535) {
                suspiciousPorts[port] = desc;
            }
        }
    }

    return !suspiciousPorts.empty();
}

std::vector<SecurityAlert> AlertManager::evaluateEvent(const NetworkEvent& event) {
    std::vector<SecurityAlert> alerts;

    int localPort = event.socket.localPort;
    int remotePort = event.socket.remotePort;

    // -------------------------------------------------------------------------
    // Rule 1: User-Configured Unexpected / Suspicious Port Detection
    // -------------------------------------------------------------------------
    auto checkPort = [&](int port, const std::string& endpointType) {
        auto it = suspiciousPorts.find(port);
        if (it != suspiciousPorts.end()) {
            SecurityAlert alert;
            alert.severity = AlertSeverity::SUSPICIOUS;
            alert.timestamp = event.timestamp;
            alert.ruleName = "UNEXPECTED_PORT";
            alert.socket = event.socket;

            std::string pidStr = (event.socket.pid > 0) ? std::to_string(event.socket.pid) : "UNKNOWN";
            alert.message = "Unexpected " + endpointType + " port detected: " +
                            std::to_string(port) + " (" + it->second + ") | Protocol: " +
                            event.socket.protocol + " | Process: " + event.socket.processName +
                            " (PID " + pidStr + ")";
            alerts.push_back(alert);
        }
    };

    if (localPort > 0) checkPort(localPort, "local");
    if (remotePort > 0) checkPort(remotePort, "remote");

    // -------------------------------------------------------------------------
    // Rule 2: New Listening Port Alert
    // -------------------------------------------------------------------------
    if (event.type == EventType::NEW_LISTENING_PORT) {
        SecurityAlert alert;
        alert.severity = AlertSeverity::WARNING;
        alert.timestamp = event.timestamp;
        alert.ruleName = "NEW_LISTENER";
        alert.socket = event.socket;

        std::string pidStr = (event.socket.pid > 0) ? std::to_string(event.socket.pid) : "UNKNOWN";
        alert.message = "New listening service opened on port: " +
                        std::to_string(event.socket.localPort) + " (" +
                        event.socket.protocol + ") by process: " +
                        event.socket.processName + " (PID " + pidStr + ")";
        alerts.push_back(alert);
    }

    // -------------------------------------------------------------------------
    // Rule 3: Newly Detected Network Process
    // -------------------------------------------------------------------------
    if (!event.socket.processName.empty() && event.socket.processName != "UNKNOWN") {
        if (knownProcesses.find(event.socket.processName) == knownProcesses.end()) {
            knownProcesses.insert(event.socket.processName);

            SecurityAlert alert;
            alert.severity = AlertSeverity::INFO;
            alert.timestamp = event.timestamp;
            alert.ruleName = "NEW_PROCESS";
            alert.socket = event.socket;

            std::string pidStr = (event.socket.pid > 0) ? std::to_string(event.socket.pid) : "-";
            alert.message = "New process associated with network activity: " +
                            event.socket.processName + " (PID " + pidStr + ")";
            alerts.push_back(alert);
        }
    }

    // -------------------------------------------------------------------------
    // Rule 4: New Network Connection Detected
    // -------------------------------------------------------------------------
    if (event.type == EventType::NEW_CONNECTION) {
        SecurityAlert alert;
        alert.severity = AlertSeverity::INFO;
        alert.timestamp = event.timestamp;
        alert.ruleName = "NEW_CONNECTION";
        alert.socket = event.socket;
        alert.message = "New network connection: " + event.socket.localIp + ":" +
                        std::to_string(event.socket.localPort) + " -> " +
                        event.socket.remoteIp + ":" + std::to_string(event.socket.remotePort) +
                        " [" + event.socket.state + "]";
        alerts.push_back(alert);
    }

    return alerts;
}

void AlertManager::printAlert(const SecurityAlert& alert) {
    std::cout << "[" << alert.timestamp << "] ";
    switch (alert.severity) {
        case AlertSeverity::SUSPICIOUS:
            std::cout << "\033[1;31m[ALERT: SUSPICIOUS]\033[0m ";
            break;
        case AlertSeverity::WARNING:
            std::cout << "\033[1;33m[ALERT: WARNING]\033[0m ";
            break;
        case AlertSeverity::INFO:
            std::cout << "\033[1;36m[ALERT: INFO]\033[0m ";
            break;
    }
    std::cout << alert.message << "\n";
}

const std::map<int, std::string>& AlertManager::getSuspiciousPorts() const {
    return suspiciousPorts;
}

void AlertManager::addSuspiciousPort(int port, const std::string& description) {
    if (port > 0 && port <= 65535) {
        suspiciousPorts[port] = description;
    }
}
