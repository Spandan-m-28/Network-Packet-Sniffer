# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -std=c11

# Include directory
INCLUDES = -Iinclude

# Libraries (libpcap will be used later)
LIBS = -lpcap

# Target executable name
TARGET = sniffer

# Automatically find all .c files in src/
SRCS = $(wildcard src/*.c)

# Convert .c files to .o files
OBJS = $(SRCS:.c=.o)

# Default rule
all: $(TARGET)

# Link object files into final executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LIBS)

# Compile each .c file into .o
src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build files
clean:
	rm -f src/*.o $(TARGET)
