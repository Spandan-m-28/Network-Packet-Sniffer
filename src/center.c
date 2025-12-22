#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void printCentered(const char *text) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    int term_width = w.ws_col;
    int text_len = strlen(text);

    if (text_len >= term_width) {
        printf("%s\n", text);  
        return;
    }

    int padding = (term_width - text_len) / 2;

    for (int i = 0; i < padding; i++)
        putchar(' ');

    printf("%s\n", text);
}
