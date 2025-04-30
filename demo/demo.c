/* hello.c
 * Debugging compile: gcc -g -no-pie -fno-PIE -O0 -o hello hello.c
 */

#include <stdio.h>

int main() {
    int n = 0xdeadbeef;
    printf("%d\n", n);
    return 0;
}
