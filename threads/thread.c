#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/fixed.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif
#define max(a,b)  (((a) > (b)) ? (a) : (b))
#define min(a,b)  (((a) < (b)) ? (a) : (b))
/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210
int load_avg;
/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* project1 : blocked 된 스레드를 모아놓은 list*/
static struct list sleep_list;
/* Sleep된 애들중에 가장 먼저 일어날 시간 저장하는 변수*/
static int64_t next_tick_to_awake;
/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);
/* 추가 선언 */
int get_priority(const struct list_elem *x);
void test_max_priority(void);
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&sleep_list);
	list_init (&destruction_req);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);

	load_avg = LOAD_AVG_DEFAULT;
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);
	test_max_priority();
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	// list_push_back (&ready_list, &t->elem); //삭제
	list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL); //priority 과제
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
// 현재 running중인 스레드를 비활성화 시키고 ready_list에 삽입
void
thread_yield (void) {
	struct thread *curr = thread_current (); //현재 실행 중인 스레드
	enum intr_level old_level; //인터럽트 level : on/off

	ASSERT (!intr_context ()); // 외부 인터럽트가 들어왔으면 True / 아니면 False

	old_level = intr_disable (); // 인터럽트가 비활성하고 이전 인터럽트 상태를 받아온다.
	/* 인터럽트 off하는 이유
		인터럽트를 disable하는 이유는 CPU의 제어권을 interrupt가 다시 enable 될 때까지 넘겨주지 않겠다는 것을 의미.
		interrupt는 스케쥴링에 필요한 time interrupt 혹은 입출력 장치에 의해 발생하는 I/O interrupt등이 포함 될 수 있다.
		위의 do_schedule함수는 CPU 제어권을 넘겨주는 함수이다. 이 과정에서 인터럽트로 인해 CPU 제어권이 엉뚱한 곳으로 넘어가면
		synchronization(동시에 두 스레드/프로세스가 하나의 공유자원에 접근하는 것을 막는)를 확보할 수 없게된다.
	*/
	if (curr != idle_thread) //현재 스레드가 idle 스레드(일을하고 있지 않은 스레드)와 같지 않다면
		// list_push_back (&ready_list, &curr->elem); // ready리스트 맨 마지막에 curr을 줄세워
		list_insert_ordered(&ready_list, &curr->elem, cmp_priority, NULL);
	do_schedule (THREAD_READY);//context switch 작업 수행 - running인 스레드를 ready로 전환.
	intr_set_level (old_level); //인자로 전달된 인터럽트 상태로 인터럽트 설정하고 이전 인터럽트 상태 변환
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	if(thread_mlfqs){
		return;
	}
	// thread_current ()->original_priority = new_priority;
	// refresh_priority();
	// test_max_priority();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
	enum intr_level old_level = intr_disable();
	thread_current()->nice = nice;
	mlfqs_calculate_priority(thread_current());
	test_max_priority();
	intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	enum intr_level old_level = intr_disable();
	int nice = thread_current()->nice;
	intr_set_level(old_level);
	return nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	enum intr_level old_level = intr_disable();
	int load_avg_value = fp_to_int_round(mult_mixed(load_avg, 100));
	intr_set_level(old_level);
	return load_avg_value;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	enum intr_level old_level = intr_disable();
	int recent_cpu = fp_to_int_round(mult_mixed(thread_current()->recent_cpu,100));
	intr_set_level(old_level);
	return recent_cpu;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;
	//priority 
	t->original_priority = priority;
	t->wait_on_lock = NULL;
	list_init(&t->donations);
	t->nice = NICE_DEFAULT;
	t->recent_cpu = RECENT_CPU_DEFAULT;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}
/* PROJECT 1 */
void update_next_tick_to_wake(int64_t ticks){
	next_tick_to_awake = min(next_tick_to_awake, ticks);
}

int64_t get_next_tick_to_awake(void){return next_tick_to_awake;}

// thread를 ticks시각까지 깨우는 함수
void thread_sleep(int64_t ticks){
	struct thread *cur = thread_current();
	// 인터럽트를 금지하고 이전 인터럽트 레벨을 저장함.
	enum intr_level old_level = intr_disable();
	ASSERT(cur != idle_thread); // cur은 idle이 아니어야 하는데, idle은 sleep 하지말아야 하기때문임
	update_next_tick_to_wake(cur->wakeup = ticks); //awake함수가 실행되어야할 tick값을 update
	list_push_back(&sleep_list, &cur->elem);
	//이 thread를 block하고 다시 scheedule 될때 까지 blocked상태로 wait
	thread_block(); //interrupt를 꺼줘야만 작동함
	// 인터럽트를 다시 받아들이도록 수정
	intr_set_level(old_level);
}

/* 푹 자고 있는 thread 중에 깨어날 시각이 ticks 시각이 지난 애들을 모조리 깨우는 함수 */
void thread_awake(int64_t wakeup_tick){
	struct list_elem *e = list_begin(&sleep_list);
	enum intr_level old_level = intr_disable();
	next_tick_to_awake = INT64_MAX;
	while (e!=list_end(&sleep_list)){
		struct thread *t = list_entry(e, struct thread, elem);
		if(wakeup_tick >= t->wakeup){ //thread가 일어날 시간이 되었는지 확인
			e = list_remove(&t->elem); //sleep list에서 제거
			thread_unblock(t); //스레드 unblock
		}else{
			e = list_next(e);
			// update_next_tick_to_wake(t->wakeup);
		}
	}
	intr_set_level(old_level);
}

/* 현재 수행중인 스레드와 가장 높은 우선순위의 스레드의 우선순위를 비교하여 스케줄링*/
void test_max_priority(void){
	if(thread_get_priority() < list_entry(list_begin(&ready_list),struct thread, elem)->priority){
		thread_yield();
	}
}
/* elem 의 priority 반환*/
int get_priority(const struct list_elem *x){
	return list_entry(x, struct thread, elem)->priority;
}
/* 인자로 주어진 스레드들의 우선순위를 비교*/
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED){
	return get_priority(a)>get_priority(b);
}

/********************************project 2-3 ****************************/
void donate_priority(void){
	/* priority donation 을 수행하는 함수를 구현한다.
	현재 스레드가 기다리고 있는 lock과 연결된 모든 스레드들을 순회하며
	현재 스레드의 우선순위를 lock을 보유하고있는 스레드에게 기부 한다.
	nexted depth는 8로 제한.*/
	struct thread *cur = thread_current();
	for (int depth=0; depth<8; depth++){
		if(!cur->wait_on_lock) break;
		struct thread *holder = cur->wait_on_lock->holder;
		holder->priority = cur->priority;
		cur = holder;
	}
}
/* lock을 해지 했을때 donations 리스트에서 해당 엔트리를 삭제 하기 위한 함수를 구현한다.*/
void remove_with_lock(struct lock *lock){
	/* 현재 thread의 donations 리스트를 확인하여 해지 할 lock을 보유하고 있는 엔트리를 삭제한다.*/
	struct thread *cur = thread_current();
	struct list_elem *d = &cur->donations;
	while(d != list_end(&cur->donations)){
		struct thread *t = list_entry(d, struct thread, donation_elem);
		if(t->wait_on_lock == lock){
			list_remove(&t->donation_elem);
		}
		d = list_next(d);
		
	}
}
bool cmp_donate_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED){
	return list_entry(a, struct thread, donation_elem)->priority >
	list_entry(b, struct thread, donation_elem)->priority;
}
/* thread의 우선순위가 변경 되었을 때 donation을 고려하여 우선순위를 다시 결정하는 함수를 작성*/
void refresh_priority(void){
	/* 현재 스레드의 우선순위를 기부받기 전의 우선순위로 변경*/
	struct thread *cur = thread_current();
	cur->priority = cur->original_priority;
	/* 가장 우선순위가 높은 donations리스트의 스레드와 현재 스레드의 우선순위를 
	비교하여 높은 값을 현재 스레드의 우선순위를 비교하여 높은 값을 현재 스레드의 우선순위로 설정한다.*/
	if (!list_empty(&cur->donations)){
		list_sort(&cur->donations, cmp_donate_priority, NULL);
		struct thread *t = list_entry(list_front(&cur->donations),struct thread, donation_elem);
		cur->priority = max(t->priority, cur->priority);
	}
}

/* thread advanced */

/* priority = PRI_MAX – (recent_cpu / 4) – (nice * 2) */
/* 특정 thread의 priority를 계산하는 함수이다. idle_thread의 priority는 고정이므로
	제외하고, fixed에서 만든 fp연산 함수를 이용하여 priority를 구한다. 계산 결과의 소수 부분ㅁ은 버림하고
	정수의 priority로 설정한다.*/
void mlfqs_calculate_priority(struct thread *t){
	if (t == idle_thread) return;
	t->priority = fp_to_int(add_mixed(div_mixed(t->recent_cpu,-4), PRI_MAX-
	t->nice * 2));
}
/* thread의 recent_cpu값을 계산하는 함수이다. fp연산을로 인해 다소 복잡해보일 수 있다.*/
void mlfqs_calculate_recent_cpu(struct thread *t){
	if(t==idle_thread) return ;
	t->recent_cpu = add_mixed(mult_fp(div_fp(mult_mixed(load_avg,2),
	add_mixed(mult_mixed(load_avg,2),1)), t->recent_cpu), t->nice);
}
void mlfqs_calculate_load_avg(void){
	int ready_threads;
	if(thread_current() == idle_thread){
		ready_threads = list_size(&ready_list);
	}else{
		ready_threads = list_size(&ready_list)+1;
	}
	load_avg = add_fp(mult_fp(div_fp(int_to_fp(59),int_to_fp(60)),load_avg),
	mult_mixed(div_fp(int_to_fp(1),int_to_fp(60)),ready_threads));
}
void mlfqs_increment_recent_cpu(void){
	if(thread_current() != idle_thread)
		thread_current()->recent_cpu = add_mixed(thread_current()->recent_cpu,1);
}
void mlfqs_recalculate_recent_cpu(void){
	struct list_elem *e;
	for(e=list_begin(&sleep_list); e!=list_end(&sleep_list); e=list_next(e)){
		struct thread *t = list_entry(e, struct thread, elem);
		mlfqs_calculate_recent_cpu(t);
	}
	for(e=list_begin(&ready_list); e!=list_end(&ready_list); e=list_next(e)){
		struct thread *t = list_entry(e, struct thread, elem);
		mlfqs_calculate_recent_cpu(t);
	}
	mlfqs_calculate_recent_cpu(thread_current());
}
void mlfqs_recalculate_priority(void){
	struct list_elem *e;
	for(e=list_begin(&sleep_list); e!=list_end(&sleep_list); e=list_next(e)){
		struct thread *t = list_entry(e, struct thread, elem);
		mlfqs_calculate_priority(t);
	}
	for(e=list_begin(&ready_list); e!=list_end(&ready_list); e=list_next(e)){
		struct thread *t = list_entry(e, struct thread, elem);
		mlfqs_calculate_priority(t);
	}
	mlfqs_calculate_priority(thread_current());
}