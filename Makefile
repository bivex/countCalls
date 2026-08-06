CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS  := -ldtrace

TARGETS  := syscall_counter syscall_callgraph syscall_optimizer demo_app unbuffered_demo buffered_demo memory_thrashing_demo thread_spam_demo

.PHONY: all clean test compare

all: $(TARGETS)

syscall_counter: syscall_counter.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

syscall_callgraph: syscall_callgraph.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

syscall_optimizer: syscall_optimizer.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

demo_app: demo_app.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

unbuffered_demo: unbuffered_demo.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

buffered_demo: buffered_demo.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

memory_thrashing_demo: memory_thrashing_demo.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

thread_spam_demo: thread_spam_demo.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -lpthread

clean:
	rm -f $(TARGETS) *.dot

compare: all
	@echo "=== 1. НЕОПТИМИЗИРОВАННАЯ ВЕРСИЯ (unbuffered_demo) ==="
	sudo ./syscall_optimizer --report ./unbuffered_demo
	@echo ""
	@echo "=== 2. ОПТИМИЗИРОВАННАЯ ВЕРСИЯ (buffered_demo) ==="
	sudo ./syscall_optimizer --report ./buffered_demo
