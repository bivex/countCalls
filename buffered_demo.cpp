/**
 * buffered_demo.cpp
 *
 * Оптимизированная версия алгоритма (в отличие от unbuffered_demo.cpp).
 *
 * Оптимизации:
 * 1. Открытие и закрытие файла выполняется РОВНО 1 РАЗ вместо 100 раз.
 * 2. Данные накапливаются в буфере памяти (std::string / std::vector<char>)
 *    и записываются за ОДИН системный вызов write() вместо 200 вызовов.
 */

#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>
#include <fcntl.h>

void buffered_write_optimized() {
    usleep(50000); // 50ms задержка для точного старта трассировки DTrace

    std::cout << "[buffered_demo] Выполняем буферизованную запись (1 вызов open/write/close)...\n";

    int fd = open("/tmp/buffered_test.tmp", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        // Накапливаем все 200 байт в одном буфере в памяти
        std::string buffer(200, 'X');

        // Записываем весь буфер за 1 системный вызов
        write(fd, buffer.data(), buffer.size());

        close(fd);
        unlink("/tmp/buffered_test.tmp");
    }
}

int main() {
    buffered_write_optimized();
    usleep(100000);
    return 0;
}
