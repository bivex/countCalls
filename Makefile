CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS  := -ldtrace

TARGETS  := syscall_counter syscall_callgraph

.PHONY: all clean

all: $(TARGETS)

syscall_counter: syscall_counter.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

syscall_callgraph: syscall_callgraph.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.dot
