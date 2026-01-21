//
// Created by owais on 1/21/2026.
//

#include "GQueue.h"
#include <stdlib.h>

Queue *queue_new(void) {
    Queue *q = (Queue*)malloc(sizeof(Queue));
    if (!q)
        return NULL;

    q->head = q->tail = NULL;
    q->length = 0;
    return q;
}

void g_queue_push_tail(Queue *q, void *data) {
    QueueNode *node = (QueueNode*)malloc(sizeof(QueueNode));
    if (!node)
        return;

    node->data = data;
    node->next = NULL;
    node->prev = q->tail;

    if (q->tail)
        q->tail->next = node;
    else
        q->head = node;

    q->tail = node;
    q->length++;
}

void *g_queue_pop_head(Queue *q) {
    if (!q || !q->head)
        return NULL;

    QueueNode *node = q->head;
    void *data = node->data;

    q->head = node->next;
    if (q->head)
        q->head->prev = NULL;
    else
        q->tail = NULL;

    free(node);
    q->length--;
    return data;
}

QueueNode *g_queue_peek_nth(const Queue *q, size_t n) {
    if (!q || n >= q->length)
        return NULL;

    QueueNode *node = q->head;
    while (n-- && node)
        node = node->next;

    return node;
}

void g_queue_clear(Queue *q) {
    if (!q)
        return;

    QueueNode *node = q->head;
    while (node) {
        QueueNode *next = node->next;
        free(node);
        node = next;
    }

    q->head = NULL;
    q->tail = NULL;
    q->length = 0;
}

void g_queue_free(Queue *q) {
    if (!q)
        return;

    QueueNode *node = q->head;
    while (node) {
        QueueNode *next = node->next;
        free(node);
        node = next;
    }

    free(q);
}
