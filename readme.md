================================================================
File: README.md
================================================================
# Systems Programming Lab B: Binary Analysis & Memory Management

## Overview
This repository contains a suite of C-based command-line utilities developed as part of a Systems Programming lab. The project focuses on low-level memory management, dynamic data structures, endianness handling, and binary file manipulation. 

The repository includes three main tools:
1.  **virusDetector**: A simulation of an antivirus engine that detects and neutralizes virus signatures in binary executables.
2.  **hexaPrint**: A utility to read and print the hexadecimal representation of binary files.
3.  **bubblesort**: A debugging exercise focused on identifying and fixing segmentation faults and memory leaks using `gdb` and `Valgrind`.

## 1. Virus Detector (`virusDetector`)
The core project of this repository. It scans suspect files byte-by-byte in memory chunks and offers an automated in-place patching mechanism to neutralize threats.

### Key Features
*   **Dynamic Data Structures:** Utilizes a custom linked list implementation to load and store an arbitrary number of virus signatures dynamically.
*   **Endianness Agnostic:** Implements dynamic parsing of binary signature files, supporting both Little-Endian (`VIRL`) and Big-Endian (`VIRB`) architectures seamlessly.
*   **Low-Level Binary Patching:** Performs in-place binary modification using `fseek` and `fwrite`, replacing the first byte of a detected virus signature with an x86 `RET` (0xC3) opcode to neutralize the payload execution flow.
*   **Memory Safety:** Strictly manages dynamic memory allocation. Verified with `Valgrind` to ensure 0 memory leaks and 0 invalid memory accesses.

### Usage
./virusDetector

An interactive menu will guide you through loading signatures, scanning files (e.g., `infected`), and neutralizing detected viruses.

## 2. Hexadecimal Printer (`hexaPrint`)
A helper program that receives the name of a binary file as a command-line argument and prints the hexadecimal value of each byte in sequence to the standard output.

### Usage
./hexaPrint <filename>


## 3. Bubblesort Debugging (`bubblesort`)
A program demonstrating memory debugging techniques. The original code contained segmentation faults and memory leaks, which were identified and resolved using interactive debugging tools.

### Usage
./bubblesort <num1> <num2> <num3> ...


## Build Instructions
The project requires `gcc` and is configured to compile for a 32-bit architecture (`-m32`), ensuring compatibility with the provided binary payloads.

To build all executables, run:
make all

To clean the compiled binaries:
make clean


================================================================
File: Makefile
================================================================
CC=gcc
CFLAGS=-Wall -Wextra -g -std=c11 -m32
TARGETS=bubblesort hexaPrint virusDetector

all: $(TARGETS)

bubblesort: lab3_bubblesort.c
	$(CC) $(CFLAGS) -o bubblesort lab3_bubblesort.c

hexaPrint: hexaPrint.c
	$(CC) $(CFLAGS) -o hexaPrint hexaPrint.c

virusDetector: antiVirus.c
	$(CC) $(CFLAGS) -o virusDetector antiVirus.c

clean:
	rm -f $(TARGETS)
