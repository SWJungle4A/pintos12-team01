#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h" // 변경사항 
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
	struct list_elem all_elem;          /* List element for all_list */ // mlfqs 관련 변경
	int64_t wakeup_tick;                /* Local ticks (minimum ticks required before awakened )  */ /* alarm-multiple 관련 변경 */

	/* donation */
	int init_priority;                  /* default priority (to initialize after return donated priority) */ // priority-donate 관련 변경
	struct lock *wait_on_lock;          /* Address of lock that this thread is waiting for */ // priority-donate 관련 변경
	struct list donations;              /* donors list (multiple donation) */ //priority-donate 관련 변경
	struct list_elem donation_elem;     /* multiple donation case */ //priority-donate 관련 변경

	/* mlfqs */
	int nice;                           /* nice value of thread */// mlfqs 관련 변경
	int recent_cpu;                     /* recent_cpu which estimates how much CPU time earned recently */// mlfqs 관련 변경

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */

	struct list child_list;             /* 자식 프로세스를 담아줄 리스트*/ //변경사항
	struct list_elem child_elem;		/* child_list 에 담아줄 elem */ // 변경사항
	
	// struct semaphore wait_sema;
	struct semaphore wait_sema;
	int exit_status;                    /* system call : exit , wait */ //변경사항

	struct intr_frame parent_if;           /* 유저 스택의 정보를 인터럽트 프레임 안에 넣어서, 커널 스택으로 넘겨주기 위함 */ //변경사항
	struct semaphore fork_sema;            /* 자식 프로세스를 정상적으로 로드하기 위해, 부모 프로세스가 sema_down/up하게 되는 세마포어 */
	struct semaphore free_sema;
	

	// 변경사항
	/* file descriptor 관련 추가 */
	struct file **fd_table;             /* File Descriptor Table (FD Table) */
	int fd_idx;                          /* File Descriptor Index (FD Idx) */

	// int stdin_count;
	// int stdout_count;

	// struct file *running;

};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

/* alarm-multiple 관련 변경 */
void thread_sleep(int64_t ticks); 
void thread_awake(int64_t ticks);
void update_next_tick_to_awake(int64_t ticks);
int64_t get_next_tick_to_awake(void);

/* alarm-priority, priority-fifo/preempt 관련 변경 */
void check_curr_max_priority(void);
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

/* priority-donate 관련 변경 */
void donate_priority(void);
void remove_donors_on_released_lock(struct lock *lock);
void refresh_priority(void);
bool cmp_donation_priority(const struct list_elem *a, const struct list_elem *b, void *aux);

/* mlfqs 관련 변경 */
void mlfqs_priority (struct thread *t); 
void mlfqs_recent_cpu (struct thread *t); 
void mlfqs_load_avg (void);
void mlfqs_increment (void);
void mlfqs_recalc(void);


/* FD(File Descriptor) 관련 변경 */
#define FDT_PAGES 3
#define FDCOUNT_LIMIT FDT_PAGES * (1<<9)


#endif /* threads/thread.h */
