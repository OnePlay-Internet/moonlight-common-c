//
// Created by owais on 1/21/2026.
//

#ifndef GQUEUE_H
#define GQUEUE_H
#include <stddef.h>

typedef struct QueueNode {
    void *data;
    struct QueueNode *next;
    struct QueueNode *prev;
} QueueNode;

typedef struct Queue {
    QueueNode *head;
    QueueNode *tail;
    size_t length;
} Queue;

#endif //GQUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

Queue *queue_new(void);

void g_queue_push_tail(Queue *q, void *data);

void *g_queue_pop_head(Queue *q);

void g_queue_clear(Queue *q);

void g_queue_free(Queue *q);

static inline size_t g_queue_get_length(const Queue *q) {
    return q ? q->length : 0;
};

QueueNode *g_queue_peek_nth(const Queue *q, size_t n);

static inline int g_queue_is_empty(const Queue *q){
    return (!q || q->length == 0);
};

#ifdef __cplusplus
}
#endif
