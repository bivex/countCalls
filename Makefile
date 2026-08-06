CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS  := -ldtrace

TARGETS  := syscall_counter syscall_callgraph syscall_optimizer demo_app

.PHONY: all clean test

all: $(TARGETS)

syscall_counter: syscall_counter.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

syscall_callgraph: syscall_callgraph.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

syscall_optimizer: syscall_optimizer.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

demo_app: demo_app.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) *.dot

test: all
	@echo "=== Тестирование syscall_optimizer ==="
	sudo ./syscall_optimizer --report ./demo_app
