/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    event_monitor.cpp
 * Purpose: Implements Module 4: Real-Time Event Monitor. Captures periodic network
 *          snapshots, compares states, and dispatches events to Modules 5 & 6.
 * ==============================================================================
 */

#include "event_monitor.h"
#include "alert_manager.h"
#include "logger.h"

#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <csignal>
#include <memory>
#include <unistd.h>

// Global volatile atomic flag for signal handling
// POSIX guarantees that sig_atomic_t reads/writes are atomic.
static volatile sig_atomic_t g_stopMonitoring = 0;

// Signal handler function for SIGINT (Ctrl+C)
static void handleSigint(int signum) {
    (void)signum; // Suppress unused parameter warning
    g_stopMonitoring = 1;
}

void setupSignalHandler() {
    // Register handleSigint to handle SIGINT (Signal #2: Terminal Interrupt Ctrl+C)
    signal(SIGINT, handleSigint);
}

bool isMonitoringStopped() {
    return g_stopMonitoring != 0;
}

void resetMonitoringStopFlag() {
    g_stopMonitoring = 0;
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t timeNow = std::chrono::system_clock::to_time_t(now);
    std::tm tmNow;
    localtime_r(&timeNow, &tmNow); // Thread-safe POSIX time conversion

    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmNow);
    return std::string(buffer);
}

NetworkSnapshot takeNetworkSnapshot() {
    NetworkSnapshot snapshot;
    snapshot.timestamp = getCurrentTimestamp();
    snapshot.activeConnections = getActiveConnections();
    snapshot.listeningPorts = getListeningPorts();
    return snapshot;
}

std::vector<NetworkEvent> compareSnapshots(const NetworkSnapshot& previous,
                                          const NetworkSnapshot& current) {
    std::vector<NetworkEvent> events;
    std::string timestamp = current.timestamp;

    // -------------------------------------------------------------------------
    // 1. Detect newly opened listening ports
    // -------------------------------------------------------------------------
    for (const auto& currPort : current.listeningPorts) {
        bool foundInPrevious = false;
        for (const auto& prevPort : previous.listeningPorts) {
            if (currPort.localPort == prevPort.localPort &&
                currPort.protocol == prevPort.protocol) {
                foundInPrevious = true;
                break;
            }
        }

        if (!foundInPrevious) {
            NetworkEvent event;
            event.type = EventType::NEW_LISTENING_PORT;
            event.timestamp = timestamp;
            event.socket = currPort;

            std::string pidStr = (currPort.pid > 0) ? std::to_string(currPort.pid) : "UNKNOWN";
            event.description = "New listening port detected: " + std::to_string(currPort.localPort) +
                                " (" + currPort.protocol + ") by process: " + currPort.processName +
                                " (PID: " + pidStr + ")";
            events.push_back(event);
        }
    }

    // -------------------------------------------------------------------------
    // 2. Detect closed listening ports
    // -------------------------------------------------------------------------
    for (const auto& prevPort : previous.listeningPorts) {
        bool foundInCurrent = false;
        for (const auto& currPort : current.listeningPorts) {
            if (prevPort.localPort == currPort.localPort &&
                prevPort.protocol == currPort.protocol) {
                foundInCurrent = true;
                break;
            }
        }

        if (!foundInCurrent) {
            NetworkEvent event;
            event.type = EventType::PORT_CLOSED;
            event.timestamp = timestamp;
            event.socket = prevPort;
            event.description = "Listening port closed: " + std::to_string(prevPort.localPort) +
                                " (" + prevPort.protocol + ")";
            events.push_back(event);
        }
    }

    // -------------------------------------------------------------------------
    // 3. Detect newly established network connections (excluding LISTEN states)
    // -------------------------------------------------------------------------
    for (const auto& currConn : current.activeConnections) {
        if (currConn.state == "LISTEN") {
            continue; // Listening sockets are already tracked above
        }

        bool foundInPrevious = false;
        for (const auto& prevConn : previous.activeConnections) {
            if (currConn.protocol == prevConn.protocol &&
                currConn.localPort == prevConn.localPort &&
                currConn.remotePort == prevConn.remotePort &&
                currConn.remoteIp == prevConn.remoteIp) {
                foundInPrevious = true;
                break;
            }
        }

        if (!foundInPrevious) {
            NetworkEvent event;
            event.type = EventType::NEW_CONNECTION;
            event.timestamp = timestamp;
            event.socket = currConn;

            std::string pidStr = (currConn.pid > 0) ? std::to_string(currConn.pid) : "-";
            event.description = "New connection detected: " + currConn.localIp + ":" +
                                std::to_string(currConn.localPort) + " -> " +
                                currConn.remoteIp + ":" + std::to_string(currConn.remotePort) +
                                " [" + currConn.state + "] Process: " + currConn.processName +
                                " (PID: " + pidStr + ")";
            events.push_back(event);
        }
    }

    return events;
}

void printEvent(const NetworkEvent& event) {
    std::cout << "[" << event.timestamp << "] ";
    switch (event.type) {
        case EventType::NEW_LISTENING_PORT:
            std::cout << "\033[1;33m[EVENT: NEW LISTENER]\033[0m ";
            break;
        case EventType::PORT_CLOSED:
            std::cout << "\033[1;34m[EVENT: PORT CLOSED]\033[0m ";
            break;
        case EventType::NEW_CONNECTION:
            std::cout << "\033[1;32m[EVENT: NEW CONNECTION]\033[0m ";
            break;
        case EventType::CONNECTION_CLOSED:
            std::cout << "\033[1;35m[EVENT: CONN CLOSED]\033[0m ";
            break;
    }
    std::cout << event.description << "\n";
}

void startRealTimeMonitoring(int intervalSeconds, int maxIterations,
                            AlertManager* alertMgr, Logger* logger) {
    setupSignalHandler();
    resetMonitoringStopFlag();

    // Use provided instances or create fallbacks
    std::unique_ptr<AlertManager> localAlertMgr;
    if (!alertMgr) {
        localAlertMgr = std::make_unique<AlertManager>("config/rules.conf");
        alertMgr = localAlertMgr.get();
    }

    std::unique_ptr<Logger> localLogger;
    if (!logger) {
        localLogger = std::make_unique<Logger>("logs/netwatch.log");
        logger = localLogger.get();
    }

    std::cout << "\n========================================================================================\n";
    std::cout << "                         MODULE 4: REAL-TIME EVENT MONITOR                              \n";
    std::cout << "========================================================================================\n";
    std::cout << "[*] Monitoring interval : " << intervalSeconds << " second(s)\n";
    std::cout << "[*] Signal handling     : SIGINT (Ctrl+C) enabled for graceful exit\n";
    std::cout << "[*] Rules loaded from   : config/rules.conf ("
              << alertMgr->getSuspiciousPorts().size() << " suspicious ports registered)\n";
    std::cout << "[*] Logging destination : " << logger->getLogPath() << "\n";
    std::cout << "[*] Status              : Initializing baseline snapshot...\n";

    // Step 1: Capture baseline snapshot
    NetworkSnapshot previousSnapshot = takeNetworkSnapshot();
    std::cout << "[+] Baseline established: " << previousSnapshot.listeningPorts.size()
              << " listening service(s), " << previousSnapshot.activeConnections.size()
              << " active socket(s).\n";
    std::cout << "----------------------------------------------------------------------------------------\n";
    std::cout << "Monitoring active. (Press Ctrl+C at any time to return to menu)\n";
    std::cout << "----------------------------------------------------------------------------------------\n";

    int iteration = 0;

    // Step 2: Periodic monitoring loop
    while (!isMonitoringStopped()) {
        // Sleep in 100ms slices so SIGINT responds immediately without waiting for full interval
        int sleepChunks = intervalSeconds * 10;
        for (int i = 0; i < sleepChunks && !isMonitoringStopped(); ++i) {
            usleep(100000); // 100 milliseconds
        }

        if (isMonitoringStopped()) {
            break;
        }

        iteration++;

        // Step 3: Capture current snapshot
        NetworkSnapshot currentSnapshot = takeNetworkSnapshot();

        // Step 4: Compare current with previous snapshot
        std::vector<NetworkEvent> events = compareSnapshots(previousSnapshot, currentSnapshot);

        if (!events.empty()) {
            for (const auto& ev : events) {
                // Print the raw event
                printEvent(ev);

                // Log the raw event to logs/netwatch.log
                logger->logEvent(ev);

                // Evaluate the event through Module 5: Alert and Rule Engine
                std::vector<SecurityAlert> alerts = alertMgr->evaluateEvent(ev);
                for (const auto& al : alerts) {
                    AlertManager::printAlert(al);
                    logger->logAlert(al);
                }
            }
        } else {
            // Heartbeat status line
            std::cout << "[" << currentSnapshot.timestamp << "] "
                      << "Scan cycle #" << iteration << ": No network changes detected. "
                      << "(" << currentSnapshot.listeningPorts.size() << " listeners, "
                      << currentSnapshot.activeConnections.size() << " active sockets)\n";
        }

        // Step 5: Save current snapshot as previous snapshot for next cycle
        previousSnapshot = currentSnapshot;

        // Check if a fixed iteration limit was requested (useful for automated testing)
        if (maxIterations > 0 && iteration >= maxIterations) {
            std::cout << "[*] Reached test limit of " << maxIterations << " scan cycles.\n";
            break;
        }
    }

    std::cout << "\n----------------------------------------------------------------------------------------\n";
    std::cout << "[+] Real-time monitoring stopped gracefully.\n";
    std::cout << "========================================================================================\n";
}
