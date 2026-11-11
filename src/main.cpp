/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    main.cpp
 * Purpose: Implements Module 7: Command-Line Interface. Coordinates all seven
 *          functional modules through an interactive terminal menu and CLI flags.
 * ==============================================================================
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <limits>
#include <unistd.h>
#include <sys/types.h>

#include "command_runner.h"
#include "network_monitor.h"
#include "process_mapper.h"
#include "event_monitor.h"
#include "alert_manager.h"
#include "logger.h"

// Helper function to pause until user presses Enter
static void pauseForUser() {
    std::cout << "\nPress Enter to return to the main menu...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

// Displays the NetWatch banner
static void displayBanner() {
    std::cout << "\n========================================================\n";
    std::cout << "                        NETWATCH                        \n";
    std::cout << "      Linux Network Activity and Security Monitor       \n";
    std::cout << "========================================================\n";
}

// Displays the interactive menu options
static void displayMenu() {
    displayBanner();
    std::cout << " 1. View Active Connections       (Module 1)\n";
    std::cout << " 2. View Listening Ports          (Module 2)\n";
    std::cout << " 3. View Process-to-Port Mapping  (Module 3 - /proc)\n";
    std::cout << " 4. Start Real-Time Monitoring    (Module 4)\n";
    std::cout << " 5. View Recent Security Alerts   (Module 5)\n";
    std::cout << " 6. View Historical Logs          (Module 6)\n";
    std::cout << " 7. Configure Monitoring Rules    (Module 5 - Rules)\n";
    std::cout << " 8. Exit\n";
    std::cout << "========================================================\n";
    std::cout << "Enter your choice [1-8]: ";
}

// Option 1: Module 1
static void handleViewConnections() {
    std::vector<ConnectionInfo> conns = getActiveConnections();
    printActiveConnections(conns);
    pauseForUser();
}

// Option 2: Module 2
static void handleViewListeningPorts() {
    std::vector<ConnectionInfo> listeners = getListeningPorts();
    printListeningPorts(listeners);
    pauseForUser();
}

// Option 3: Module 3
static void handleProcessMapping() {
    std::vector<ConnectionInfo> mappings = getProcessPortMappings();
    printProcessPortMapping(mappings);
    pauseForUser();
}

// Option 4: Module 4
static void handleRealTimeMonitoring(AlertManager& alertMgr, Logger& logger) {
    int interval = 3;
    std::cout << "\nEnter monitoring refresh interval in seconds (default 3): ";
    std::string input;
    std::getline(std::cin, input);
    if (!input.empty()) {
        try {
            int val = std::stoi(input);
            if (val >= 1 && val <= 60) {
                interval = val;
            }
        } catch (...) {
            interval = 3;
        }
    }

    // Run continuous monitoring (0 = infinite until Ctrl+C)
    startRealTimeMonitoring(interval, 0, &alertMgr, &logger);
    pauseForUser();
}

// Option 5: Module 5 (Filter alerts from log file)
static void handleViewAlerts(const Logger& logger) {
    std::cout << "\n========================================================================================\n";
    std::cout << "                         MODULE 5: RECENT SECURITY ALERTS                               \n";
    std::cout << "========================================================================================\n";

    std::ifstream file(logger.getLogPath());
    if (!file.is_open()) {
        std::cout << "[!] No alert log found. Run real-time monitoring to record activity.\n";
        std::cout << "========================================================================================\n";
        pauseForUser();
        return;
    }

    std::string line;
    int alertCount = 0;
    while (std::getline(file, line)) {
        if (line.find("ALERT_") != std::string::npos || line.find("[ALERT:") != std::string::npos) {
            alertCount++;
            if (line.find("ALERT_SUSPICIOUS") != std::string::npos) {
                std::cout << "\033[1;31m" << line << "\033[0m\n";
            } else if (line.find("ALERT_WARNING") != std::string::npos) {
                std::cout << "\033[1;33m" << line << "\033[0m\n";
            } else {
                std::cout << "\033[1;36m" << line << "\033[0m\n";
            }
        }
    }

    if (alertCount == 0) {
        std::cout << "[+] No security alerts recorded yet.\n";
    } else {
        std::cout << "\nTotal security alerts recorded: " << alertCount << "\n";
    }

    std::cout << "========================================================================================\n";
    pauseForUser();
}

// Option 6: Module 6
static void handleViewLogs(const Logger& logger) {
    logger.viewHistoricalLogs(50);
    pauseForUser();
}

// Option 7: Module 5 Rule Configuration
static void handleConfigureRules(AlertManager& alertMgr) {
    std::cout << "\n========================================================================================\n";
    std::cout << "                     MODULE 5: SUSPICIOUS PORT RULES CONFIGURATION                      \n";
    std::cout << "Source: config/rules.conf\n";
    std::cout << "========================================================================================\n";
    std::cout << std::left << std::setw(10) << "PORT" << "DESCRIPTION" << "\n";
    std::cout << "----------------------------------------------------------------------------------------\n";

    const auto& rules = alertMgr.getSuspiciousPorts();
    for (const auto& pair : rules) {
        std::cout << std::left << std::setw(10) << pair.first << pair.second << "\n";
    }
    std::cout << "----------------------------------------------------------------------------------------\n";
    std::cout << "Total Configured Rules: " << rules.size() << "\n\n";

    std::cout << "Options:\n";
    std::cout << "1. Add a new suspicious port rule\n";
    std::cout << "2. Reload rules from file\n";
    std::cout << "3. Return to main menu\n";
    std::cout << "Enter choice: ";

    std::string subChoice;
    std::getline(std::cin, subChoice);

    if (subChoice == "1") {
        std::cout << "Enter port number (1-65535): ";
        std::string portStr;
        std::getline(std::cin, portStr);

        std::cout << "Enter short description (no spaces, e.g. Custom_Backdoor): ";
        std::string desc;
        std::getline(std::cin, desc);

        try {
            int port = std::stoi(portStr);
            if (port > 0 && port <= 65535 && !desc.empty()) {
                alertMgr.addSuspiciousPort(port, desc);

                // Append to config/rules.conf
                std::ofstream cfgFile("config/rules.conf", std::ios::app);
                if (cfgFile.is_open()) {
                    cfgFile << "PORT " << port << " " << desc << "\n";
                    std::cout << "[+] Rule successfully added and persisted to config/rules.conf!\n";
                } else {
                    std::cout << "[+] Rule added for current session (could not open config/rules.conf for writing).\n";
                }
            } else {
                std::cout << "[!] Invalid port number or empty description.\n";
            }
        } catch (...) {
            std::cout << "[!] Invalid port input.\n";
        }
    } else if (subChoice == "2") {
        if (alertMgr.loadRules("config/rules.conf")) {
            std::cout << "[+] Rules successfully reloaded from config/rules.conf.\n";
        } else {
            std::cout << "[!] Failed to reload rules from config/rules.conf.\n";
        }
    }

    pauseForUser();
}

// Displays command-line help
static void displayHelp(const char* progName) {
    std::cout << "Usage: " << progName << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  (no arguments)       Start the interactive terminal interface\n"
              << "  -c, --connections    Display active network connections (Module 1)\n"
              << "  -l, --listening      Display listening ports (Module 2)\n"
              << "  -m, --mapping        Display /proc socket-to-PID mapping (Module 3)\n"
              << "  -r, --monitor [SEC]  Start real-time event monitoring (Module 4)\n"
              << "  -a, --alerts         Display recorded security alerts (Module 5)\n"
              << "  -h, --history [N]    Display recent historical logs (Module 6)\n"
              << "  --help               Show this help message\n";
}

int main(int argc, char* argv[]) {
    AlertManager alertMgr("config/rules.conf");
    Logger logger("logs/netwatch.log");

    // Check for Command-Line Arguments
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "--help") {
            displayHelp(argv[0]);
            return 0;
        } else if (arg == "-c" || arg == "--connections") {
            std::vector<ConnectionInfo> conns = getActiveConnections();
            printActiveConnections(conns);
            return 0;
        } else if (arg == "-l" || arg == "--listening") {
            std::vector<ConnectionInfo> listeners = getListeningPorts();
            printListeningPorts(listeners);
            return 0;
        } else if (arg == "-m" || arg == "--mapping") {
            std::vector<ConnectionInfo> mappings = getProcessPortMappings();
            printProcessPortMapping(mappings);
            return 0;
        } else if (arg == "-r" || arg == "--monitor") {
            int interval = 3;
            int maxCycles = 0;
            if (argc > 2) {
                try { interval = std::stoi(argv[2]); } catch (...) { interval = 3; }
            }
            if (argc > 3) {
                try { maxCycles = std::stoi(argv[3]); } catch (...) { maxCycles = 0; }
            }
            startRealTimeMonitoring(interval, maxCycles, &alertMgr, &logger);
            return 0;
        } else if (arg == "-a" || arg == "--alerts") {
            handleViewAlerts(logger);
            return 0;
        } else if (arg == "-h" || arg == "--history") {
            int lines = 50;
            if (argc > 2) {
                try { lines = std::stoi(argv[2]); } catch (...) { lines = 50; }
            }
            logger.viewHistoricalLogs(lines);
            return 0;
        } else {
            std::cout << "[!] Unknown argument: " << arg << "\n";
            displayHelp(argv[0]);
            return 1;
        }
    }

    // Interactive Menu Loop
    bool running = true;
    while (running) {
        displayMenu();

        std::string input;
        if (!std::getline(std::cin, input)) {
            // End of input (Ctrl+D)
            std::cout << "\n[+] Exiting NetWatch. Goodbye!\n";
            break;
        }

        if (input.empty()) {
            continue;
        }

        int choice = 0;
        try {
            choice = std::stoi(input);
        } catch (...) {
            choice = 0;
        }

        switch (choice) {
            case 1:
                handleViewConnections();
                break;
            case 2:
                handleViewListeningPorts();
                break;
            case 3:
                handleProcessMapping();
                break;
            case 4:
                handleRealTimeMonitoring(alertMgr, logger);
                break;
            case 5:
                handleViewAlerts(logger);
                break;
            case 6:
                handleViewLogs(logger);
                break;
            case 7:
                handleConfigureRules(alertMgr);
                break;
            case 8:
                std::cout << "\n[+] Thank you for using NetWatch. Exiting cleanly.\n";
                running = false;
                break;
            default:
                std::cout << "\n[!] Invalid selection. Please enter a number between 1 and 8.\n";
                pauseForUser();
                break;
        }
    }

    return 0;
}
