CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra
LDFLAGS  := -ldtrace
TARGET   := syscall_counter
SRC      := syscall_counter.cpp

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	@echo "Использование: sudo ./$(TARGET) <program> [args...]"
