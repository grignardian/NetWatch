# ==============================================================================
# Project: NetWatch - Linux Network Activity and Security Monitoring System
# Course:  Unix Programming Lab (24B15CS214)
# Program: B.Tech CSE (Cyber Security) - 2nd Year (3rd Semester)
# ==============================================================================

# Compiler and Flags
CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -pedantic -O2
INCLUDES = -Isrc

# Target Executable
TARGET   = netwatch

# Source and Object Files
SRCS     = $(wildcard src/*.cpp)
OBJS     = $(SRCS:.cpp=.o)

# Default Rule: Build the target executable
all: $(TARGET)

# Linking step: Combines compiled object files into the final binary
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(TARGET)
	@echo "--------------------------------------------------------"
	@echo "Build successful! Run './$(TARGET)' to start NetWatch."
	@echo "--------------------------------------------------------"

# Compilation step: Compiles each .cpp file into a .o object file
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Create necessary directories
init:
	mkdir -p config logs

# Clean rule: Removes all compiled object files and the executable
clean:
	rm -f src/*.o $(TARGET)
	@echo "Cleaned build artifacts (object files and executable)."

# Run automated verification suite
test:
	./tests/test_netwatch.sh

# Display help information about Makefile targets
help:
	@echo "NetWatch Build Options:"
	@echo "  make        - Compiles all source files and produces '$(TARGET)'"
	@echo "  make test   - Runs the automated test suite"
	@echo "  make clean  - Deletes all .o object files and the '$(TARGET)' binary"
	@echo "  make init   - Creates the config/ and logs/ directories if missing"
	@echo "  make help   - Shows this help message"

.PHONY: all clean init test help
