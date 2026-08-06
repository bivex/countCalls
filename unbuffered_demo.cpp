#include <iostream>
#include <unistd.h>
#include <fcntl.h>

void stat_and_open_loop() {
    usleep(50000); // 50ms задержка для гарантированного старта DTrace
    std::cout << "[demo] Выполняем 100 избыточных вызовов open/close...\n";
    for (int i = 0; i < 100; ++i) {
        int fd = open("/tmp/unbuffered_test.tmp", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            close(fd);
        }
    }
    unlink("/tmp/unbuffered_test.tmp");
}

int main() {
    stat_and_open_loop();
    usleep(100000); // 100ms задержка перед выходом для сброса DTrace буферов
    return 0;
}
