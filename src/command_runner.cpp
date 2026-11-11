/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    command_runner.cpp
 * Purpose: Implements command execution via fork(), execvp(), pipe(), and dup2().
 * ==============================================================================
 */

#include "command_runner.h"

#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

bool runCommand(const std::vector<std::string>& args, std::string& output) {
    output.clear();

    if (args.empty()) {
        return false;
    }

    // Array to hold the two file descriptors for the pipe:
    // pipefd[0] = Read end of pipe
    // pipefd[1] = Write end of pipe
    int pipefd[2];

    // Create an anonymous unidirectional data channel (pipe)
    if (pipe(pipefd) == -1) {
        perror("NetWatch Error: pipe() failed");
        return false;
    }

    // Fork the current process to create a child process
    pid_t pid = fork();

    if (pid < 0) {
        // Fork failed
        perror("NetWatch Error: fork() failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (pid == 0) {
        // -------------------------------------------------------------
        // CHILD PROCESS (pid == 0)
        // -------------------------------------------------------------
        // The child's job is to run the desired command (e.g., 'ss')
        // and redirect its output into the pipe.

        // Step 1: Close the unused read end of the pipe in child
        close(pipefd[0]);

        // Step 2: Redirect standard output (stdout, fd 1) to the write end of the pipe
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
            perror("NetWatch Child Error: dup2(stdout) failed");
            close(pipefd[1]);
            _exit(127);
        }

        // Also redirect stderr to pipe so error messages don't leak to the terminal
        dup2(pipefd[1], STDERR_FILENO);

        // Step 3: Close the original pipefd[1] descriptor as it is now duplicated
        close(pipefd[1]);

        // Step 4: Prepare arguments array for execvp (must end with nullptr)
        std::vector<char*> c_args;
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }
        c_args.push_back(nullptr);

        // Step 5: Replace child process image with the specified command
        execvp(c_args[0], c_args.data());

        // If execvp returns, an error occurred (e.g., binary not found)
        perror("NetWatch Child Error: execvp() failed");
        _exit(127);
    } else {
        // -------------------------------------------------------------
        // PARENT PROCESS (pid > 0)
        // -------------------------------------------------------------
        // The parent's job is to read the output sent by the child
        // through the read end of the pipe, then wait for the child to finish.

        // Step 1: Crucial - Close the write end in the parent!
        // If parent does not close pipefd[1], read() will never see EOF (End-Of-File)
        // and will hang indefinitely.
        close(pipefd[1]);

        // Step 2: Read data from pipefd[0] using the POSIX read() system call
        char buffer[4096];
        ssize_t bytesRead = 0;

        while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytesRead] = '\0';
            output.append(buffer, bytesRead);
        }

        // Step 3: Close read end of pipe once reading is finished
        close(pipefd[0]);

        // Step 4: Wait for child process to terminate to prevent a zombie process
        int status = 0;
        waitpid(pid, &status, 0);

        // Check if child exited normally
        if (WIFEXITED(status)) {
            return true;
        }

        return false;
    }
}
