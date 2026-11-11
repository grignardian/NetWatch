/*
 * ==============================================================================
 * Project: NetWatch - Linux Network Activity and Security Monitoring System
 * Course:  Unix Programming Lab (24B15CS214) - 3rd Semester B.Tech CSE (Cyber Sec)
 * File:    command_runner.h
 * Purpose: Declares helper functions to execute Linux system commands using pure
 *          Unix system programming calls (fork, execvp, pipe, dup2, waitpid).
 * ==============================================================================
 */

#ifndef COMMAND_RUNNER_H
#define COMMAND_RUNNER_H

#include <string>
#include <vector>

/*
 * Function: runCommand
 * -------------------
 * Executes a system program with the given arguments without using the shell.
 *
 * Parameters:
 *   args   : Vector of arguments. args[0] is the binary (e.g., "ss"),
 *            followed by options (e.g., "-tunap").
 *   output : Reference to a string where the command's standard output will be stored.
 *
 * Returns:
 *   true  : If the command was executed and exited normally.
 *   false : If pipe(), fork(), or execvp() failed.
 *
 * Unix Concepts Demonstrated:
 *   - pipe()    : Unidirectional IPC channel between child and parent.
 *   - fork()    : Creates an exact copy of the calling process (child process).
 *   - dup2()    : Duplicates the pipe file descriptor onto STDOUT_FILENO (fd 1).
 *   - execvp()  : Replaces child process image with the target command binary.
 *   - read()    : Low-level POSIX system call to read bytes from the pipe descriptor.
 *   - close()   : Closes unused file descriptors to prevent descriptor leaks and hangs.
 *   - waitpid() : Synchronizes parent with child, preventing zombie processes.
 */
bool runCommand(const std::vector<std::string>& args, std::string& output);

#endif // COMMAND_RUNNER_H
