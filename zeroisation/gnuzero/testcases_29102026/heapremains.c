#define _DEFAULT_SOURCE          /* for explicit_bzero on glibc */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A task: what to run, its data, and a link to the next task in the queue */
typedef struct Task {
    void (*run)(struct Task *);
    int id;
    char payload[32];
    struct Task *next;
} Task;

/* Simple FIFO queue (linked list). Global, so it outlives every function. */
typedef struct {
    Task *head;
    Task *tail;
} Queue;

static Queue queue = { NULL, NULL };

static void enqueue(Task *t)
{
    t->next = NULL;
    if (queue.tail)
        queue.tail->next = t;
    else
        queue.head = t;
    queue.tail = t;
}

static Task *dequeue(void)
{
    Task *t = queue.head;
    if (t) {
        queue.head = t->next;
        if (!queue.head)
            queue.tail = NULL;
    }
    return t;
}

/* The work a task does when it finally runs */
static void print_task(Task *t)
{
    printf("[run]    task %d: \"%s\"  (heap %p)\n", t->id, t->payload, (void *)t);
}

/*
 * Creates a task on the heap, queues it, and returns.
 * When this function returns, its stack frame is gone:
 *   - 'marker' (a stack local) no longer exists
 *   - 't' (the pointer variable itself) no longer exists
 *   - but *t, the Task on the heap, is still alive, reachable through the queue
 */
static void submit_task(int id, const char *msg)
{
    int marker = id;                       /* lives on the stack */
    Task *t = malloc(sizeof *t);           /* lives on the heap  */
    if (!t) {
        perror("malloc");
        exit(1);
    }
    t->run = print_task;
    t->id = id;
    snprintf(t->payload, sizeof t->payload, "%s", msg);
    enqueue(t);

    printf("[submit] task %d: heap %p, stack local at %p\n",
           id, (void *)t, (void *)&marker);
}


int main(void)
{   
    submit_task(1,"aaaaaaa");
    submit_task(2,"bbbbbbb");
    Task *t;
    while ((t = dequeue()) != NULL) {
        t->run(t);
        printf("before zeroing   task %d: heap %p\n", t->id, (void *)t);
        //explicit_bzero(t, sizeof *t);      /* wipe before freeing */
        free(t);                           /* heap lifetime ends here */
        printf("after freeing   task %d: heap %p\n", t->id, (void *)t);
    }

    abort();  /* crash here to see what remains on the heap */
    return 0;

}


