#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>
#include "backtrace.h"
#include "netos_status.h"

void netos_backtrace()
{
    void *buffers[100];
    int num_frames;

    num_frames = backtrace(buffers, 100);

    backtrace_symbols_fd(buffers, num_frames, STDERR_FILENO);

    exit(EXIT_FAILURE);
}

