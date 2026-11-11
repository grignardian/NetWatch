/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    logger.cpp
 * Purpose: Implements Module 6: Logging and History. Maintains logs/netwatch.log.
 * ==============================================================================
 */

#include "logger.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>

Logger::Logger(const std::string& logFilePath)
    : logPath(logFilePath) {
    ensureLogDirectoryExists(logPath);
}

bool Logger::ensureLogDirectoryExists(const std::string& filePath) {
    size_t slashPos = filePath.rfind('/');
    if (slashPos != std::string::npos) {
        std::string dirPath = filePath.substr(0, slashPos);
        // POSIX mkdir system call: creates directory with permissions rwxr-xr-x (0755)
        int res = mkdir(dirPath.c_str(), 0755);
        if (res == -1 && errno != EEXIST) {
            return false;
        }
    }
    return true;
}

bool Logger::logEvent(const NetworkEvent& event) {
    ensureLogDirectoryExists(logPath);

    // Open file in append mode (std::ios::app) to preserve existing history
    std::ofstream file(logPath, std::ios::app);
    if (!file.is_open()) {
        std::cerr << "NetWatch Error: Failed to open log file at " << logPath << "\n";
        return false;
    }

    std::string pidStr = (event.socket.pid > 0) ? std::to_string(event.socket.pid) : "-";
    std::string localAddr = event.socket.localIp + ":" + std::to_string(event.socket.localPort);
    std::string remoteAddr = (event.socket.remotePort == 0 && event.socket.remoteIp == "*")
                             ? "*:*"
                             : (event.socket.remoteIp + ":" + std::to_string(event.socket.remotePort));

    std::string eventTypeStr;
    switch (event.type) {
        case EventType::NEW_LISTENING_PORT: eventTypeStr = "NEW_LISTENER"; break;
        case EventType::PORT_CLOSED:        eventTypeStr = "PORT_CLOSED"; break;
        case EventType::NEW_CONNECTION:     eventTypeStr = "NEW_CONNECTION"; break;
        case EventType::CONNECTION_CLOSED:   eventTypeStr = "CONN_CLOSED"; break;
    }

    // Format: TIMESTAMP | EVENT_TYPE | PROTOCOL | LOCAL_ADDR | REMOTE_ADDR | PID | PROCESS | DESCRIPTION
    file << "[" << event.timestamp << "] | "
         << eventTypeStr << " | "
         << event.socket.protocol << " | "
         << localAddr << " | "
         << remoteAddr << " | "
         << "PID:" << pidStr << " | "
         << event.socket.processName << " | "
         << event.description << "\n";

    file.flush();
    return true;
}

bool Logger::logAlert(const SecurityAlert& alert) {
    ensureLogDirectoryExists(logPath);

    std::ofstream file(logPath, std::ios::app);
    if (!file.is_open()) {
        return false;
    }

    std::string severityStr;
    switch (alert.severity) {
        case AlertSeverity::SUSPICIOUS: severityStr = "ALERT_SUSPICIOUS"; break;
        case AlertSeverity::WARNING:    severityStr = "ALERT_WARNING"; break;
        case AlertSeverity::INFO:       severityStr = "ALERT_INFO"; break;
    }

    std::string pidStr = (alert.socket.pid > 0) ? std::to_string(alert.socket.pid) : "-";
    std::string localAddr = alert.socket.localIp + ":" + std::to_string(alert.socket.localPort);
    std::string remoteAddr = (alert.socket.remotePort == 0 && alert.socket.remoteIp == "*")
                             ? "*:*"
                             : (alert.socket.remoteIp + ":" + std::to_string(alert.socket.remotePort));

    file << "[" << alert.timestamp << "] | "
         << severityStr << " | "
         << alert.socket.protocol << " | "
         << localAddr << " | "
         << remoteAddr << " | "
         << "PID:" << pidStr << " | "
         << alert.socket.processName << " | "
         << alert.message << "\n";

    file.flush();
    return true;
}

void Logger::viewHistoricalLogs(int maxLines) const {
    std::cout << "\n========================================================================================\n";
    std::cout << "                         MODULE 6: HISTORICAL AUDIT LOGS                                \n";
    std::cout << "Source: " << logPath << "\n";
    std::cout << "========================================================================================\n";

    std::ifstream file(logPath);
    if (!file.is_open()) {
        std::cout << "[!] No log entries found. Start real-time monitoring to record events.\n";
        std::cout << "========================================================================================\n";
        return;
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            lines.push_back(line);
        }
    }

    if (lines.empty()) {
        std::cout << "Log file is currently empty.\n";
    } else {
        size_t startIndex = 0;
        if (maxLines > 0 && lines.size() > static_cast<size_t>(maxLines)) {
            startIndex = lines.size() - maxLines;
            std::cout << "[*] Showing most recent " << maxLines << " of " << lines.size() << " total log entries:\n\n";
        } else {
            std::cout << "[*] Showing all " << lines.size() << " log entries:\n\n";
        }

        for (size_t i = startIndex; i < lines.size(); ++i) {
            std::cout << lines[i] << "\n";
        }
    }

    std::cout << "========================================================================================\n";
}

bool Logger::clearLogs() {
    std::ofstream file(logPath, std::ios::trunc);
    return file.is_open();
}

const std::string& Logger::getLogPath() const {
    return logPath;
}
