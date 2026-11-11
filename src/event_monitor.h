/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    event_monitor.h
 * Purpose: Declares structures and functions for Module 4: Real-Time Event Monitor.
 *          Handles snapshot comparison, continuous periodic monitoring, and
 *          graceful shutdown on SIGINT (Ctrl+C).
 * ==============================================================================
 */

#ifndef EVENT_MONITOR_H
#define EVENT_MONITOR_H

#include "network_monitor.h"
#include <string>
#include <vector>

// Forward declarations
class AlertManager;
class Logger;

// Types of detectable network events
enum class EventType {
    NEW_LISTENING_PORT, // A new listening port appeared
    PORT_CLOSED,        // An existing listening port was closed
    NEW_CONNECTION,     // A new network connection was established
    CONNECTION_CLOSED   // An active connection was terminated
};

// Represents a detected change event
struct NetworkEvent {
    EventType type;
    std::string timestamp;   // Human-readable timestamp (YYYY-MM-DD HH:MM:SS)
    ConnectionInfo socket;   // Details of the associated socket
    std::string description; // Informative message describing the event
};

// Represents a complete network state snapshot at a specific point in time
struct NetworkSnapshot {
    std::vector<ConnectionInfo> activeConnections;
    std::vector<ConnectionInfo> listeningPorts;
    std::string timestamp;
};

/*
 * Returns the current local system timestamp formatted as "YYYY-MM-DD HH:MM:SS".
 */
std::string getCurrentTimestamp();

/*
 * Captures an instantaneous snapshot of current active connections and listening ports.
 */
NetworkSnapshot takeNetworkSnapshot();

/*
 * Compares two consecutive snapshots to detect deltas:
 * - Newly opened listening ports
 * - Closed listening ports
 * - Newly established connections
 */
std::vector<NetworkEvent> compareSnapshots(const NetworkSnapshot& previous,
                                          const NetworkSnapshot& current);

/*
 * Prints a formatted notification for a detected network event.
 */
void printEvent(const NetworkEvent& event);

/*
 * Signal handler for SIGINT (Ctrl+C) to stop real-time monitoring gracefully.
 */
void setupSignalHandler();

/*
 * Checks if a stop signal has been received.
 */
bool isMonitoringStopped();

/*
 * Resets the stop flag before starting a new monitoring session.
 */
void resetMonitoringStopFlag();

/*
 * Module 4 Core Function:
 * Executes the continuous real-time monitoring loop and dispatches events to
 * the Alert Engine (Module 5) and the Persistent Logger (Module 6).
 *
 * Parameters:
 *   intervalSeconds : Sleep duration between snapshots (default 3 seconds).
 *   maxIterations   : Maximum loop count (pass 0 for infinite until Ctrl+C).
 *   alertMgr        : Optional pointer to AlertManager instance.
 *   logger          : Optional pointer to Logger instance.
 */
void startRealTimeMonitoring(int intervalSeconds = 3, int maxIterations = 0,
                            AlertManager* alertMgr = nullptr, Logger* logger = nullptr);

#endif // EVENT_MONITOR_H
