#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/pid.h>

struct k22info {
    char comm[64];                  /* name of the executable */
    pid_t pid;                      /* process ID */
    pid_t parent_pid;               /* parent process ID */
    pid_t first_child_pid;          /* PID of first child */
    pid_t next_sibling_pid;         /* PID of next sibling */
    unsigned long nvcsw;            /* number of voluntary context switches */
    unsigned long nivcsw;           /* number of involuntary context switches */
    unsigned long start_time;       /* monotonic start time in nanoseconds */
};
