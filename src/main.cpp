/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * File:    main.cpp
 * Purpose: Interactive terminal menu and command-line argument dispatcher.
 * ==============================================================================
 */

#include "netwatch.h"

#include <iostream>
#include <string>

using namespace std;

static void pauseForUser() {
    cout << "\nPress Enter to return to menu...";
    cin.ignore(10000, '\n');
}

static void showMenu() {
    cout << "\n========================================================\n";
    cout << "                        NETWATCH                        \n";
    cout << "      Linux Network Activity and Security Monitor       \n";
    cout << "========================================================\n";
    cout << " 1. View Active Connections       (Module 1)\n";
    cout << " 2. View Listening Ports          (Module 2)\n";
    cout << " 3. View Process-to-Port Mapping  (Module 3 - /proc)\n";
    cout << " 4. Start Real-Time Monitoring    (Module 4)\n";
    cout << " 5. View Recent Security Alerts   (Module 5)\n";
    cout << " 6. View Historical Logs          (Module 6)\n";
    cout << " 7. View Configured Rules         (Module 5 - Rules)\n";
    cout << " 8. Exit\n";
    cout << "========================================================\n";
    cout << "Enter your choice [1-8]: ";
}

int main(int argc, char* argv[]) {
    loadRules("config/rules.conf");

    // Handle command-line arguments (e.g. ./netwatch -c, ./netwatch -l)
    if (argc > 1) {
        string arg = argv[1];
        if (arg == "-c" || arg == "--connections") {
            printConnections(getActiveConnections());
            return 0;
        } else if (arg == "-l" || arg == "--listening") {
            printListeningPorts(getListeningPorts());
            return 0;
        } else if (arg == "-m" || arg == "--mapping") {
            printProcessMappings(getProcessMappings());
            return 0;
        } else if (arg == "-r" || arg == "--monitor") {
            int sec = 3;
            int cycles = 0;
            if (argc > 2) {
                try { sec = stoi(argv[2]); } catch (...) { sec = 3; }
            }
            if (argc > 3) {
                try { cycles = stoi(argv[3]); } catch (...) { cycles = 0; }
            }
            runRealTimeMonitor(sec, cycles);
            return 0;
        } else if (arg == "-a" || arg == "--alerts" || arg == "-h" || arg == "--history") {
            int lines = 20;
            if (argc > 2) {
                try { lines = stoi(argv[2]); } catch (...) { lines = 20; }
            }
            viewLogs(lines);
            return 0;
        } else {
            cout << "Usage: " << argv[0] << " [-c|-l|-m|-r|-a|-h|--help]\n";
            return 0;
        }
    }

    // Interactive Menu Loop
    while (true) {
        showMenu();

        string input;
        if (!getline(cin, input)) break; // Handle Ctrl+D (EOF)
        if (input.empty()) continue;

        int choice = 0;
        try { choice = stoi(input); } catch (...) { choice = 0; }

        switch (choice) {
            case 1:
                printConnections(getActiveConnections());
                pauseForUser();
                break;
            case 2:
                printListeningPorts(getListeningPorts());
                pauseForUser();
                break;
            case 3:
                printProcessMappings(getProcessMappings());
                pauseForUser();
                break;
            case 4: {
                cout << "\nEnter monitoring interval in seconds (default 3): ";
                string secInput;
                getline(cin, secInput);
                int sec = 3;
                try { if (!secInput.empty()) sec = stoi(secInput); } catch (...) { sec = 3; }
                runRealTimeMonitor(sec, 0);
                pauseForUser();
                break;
            }
            case 5:
            case 6:
                viewLogs(30);
                pauseForUser();
                break;
            case 7:
                viewRules();
                pauseForUser();
                break;
            case 8:
                cout << "\n[+] Thank you for using NetWatch. Exiting cleanly.\n";
                return 0;
            default:
                cout << "\n[!] Invalid choice. Please enter a number between 1 and 8.\n";
                pauseForUser();
                break;
        }
    }

    return 0;
}
