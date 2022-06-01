#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void check_address(void *addr); // 변경사항
struct lock filesys_lock;

#endif /* userprog/syscall.h */
