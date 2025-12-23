#include <stdio.h>
#include <stdlib.h>
#include "cli.h"
#include "config.h"
#include "capture.h"

int main(int argc,char *argv[]){
    Config cfg;
    initConfig(&cfg);

    int status = parseArguments(argc, argv, &cfg);
    if (status == -1) {
        return EXIT_FAILURE;
    }
    if (status == 0) {
        return EXIT_SUCCESS;
    }


    // start packet packet capture 
    startCapture(&cfg);

    return 0;
}