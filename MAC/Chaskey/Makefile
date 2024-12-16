# Compiler and flags
CC = clang
CFLAGS = -O2 -Wall
BPF_CFLAGS = -target bpf -g -c

# File names
NATIVE_SRC = chaskey_original.c
EBPF_SRC = chaskey.bpf.c
NATIVE_BIN = chaskey
EBPF_OBJ = chaskey.bpf.o
EBPF_RUNNER_SOURCE = loader.c
EBPF_RUNNER = chaskey_ebpf

# Network interface
INTERFACE = wlp0s20f3

.PHONY: all compile run compile_native compile_ebpf run_native run_ebpf unload_ebpf clean

# Default target
all: run

# Compilation rules
compile: compile_native compile_ebpf

compile_native:
	$(CC) $(CFLAGS) $(NATIVE_SRC) -o $(NATIVE_BIN)

compile_ebpf:
	$(CC) $(CFLAGS) $(BPF_CFLAGS) $(EBPF_SRC) -o $(EBPF_OBJ)
	$(CC) $(CFLAGS) -I/usr/include -I/usr/include/bpf $(EBPF_RUNNER_SOURCE) -o $(EBPF_RUNNER) -lbpf

# Run rules
run: compile run_native run_ebpf

run_native:
	./$(NATIVE_BIN)

run_ebpf: unload_ebpf
	sudo ./$(EBPF_RUNNER)

unload_ebpf:
	sudo ip link set dev $(INTERFACE) xdp off

# Cleanup rule
clean:
	rm -f $(NATIVE_BIN) $(EBPF_OBJ)
