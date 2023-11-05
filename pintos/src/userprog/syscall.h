#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>

void syscall_init (void);
void syscall_exit(int status);
void close_all_files(struct list *files);

#endif /* userprog/syscall.h */
