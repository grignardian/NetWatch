/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    logger.h
 * Purpose: Declares functions and classes for Module 6: Logging and History.
 *          Appends timestamped events to logs/netwatch.log and provides history viewing.
 * ==============================================================================
 */

#ifndef LOGGER_H
#define LOGGER_H

#include "event_monitor.h"
#include "alert_manager.h"
#include <string>

class Logger {
public:
    // Initializes the logger with the specified file path
    explicit Logger(const std::string& logFilePath = "logs/netwatch.log");

    // Automatically ensures that the parent directory (e.g. logs/) exists
    static bool ensureLogDirectoryExists(const std::string& filePath);

    // Appends a detected network event to the persistent log file
    bool logEvent(const NetworkEvent& event);

    // Appends a security alert to the persistent log file
    bool logAlert(const SecurityAlert& alert);

    // Displays the contents of the historical log file to the terminal
    // Parameters:
    //   maxLines : Maximum number of recent lines to display (0 for all)
    void viewHistoricalLogs(int maxLines = 50) const;

    // Clears the historical log file (useful for resetting test runs)
    bool clearLogs();

    // Returns the path to the current log file
    const std::string& getLogPath() const;

private:
    std::string logPath;
};

#endif // LOGGER_H
