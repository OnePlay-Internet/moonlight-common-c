//
// Created by owais on 1/21/2026.
//

#include "GSList.h"

#include <stdlib.h>

ListNode *list_prepend(ListNode *list, void *data) {
    ListNode *node = malloc(sizeof(ListNode));
    if (!node)
        return list;   /* or handle OOM */

    node->data = data;
    node->next = list;
    return node;       /* new head */
}

static ListNode *list_merge_sorted(
    ListNode *a,
    ListNode *b,
    int (*cmp)(const void *, const void *)
) {
    if (!a) return b;
    if (!b) return a;

    ListNode *result;

    if (cmp(a->data, b->data) <= 0) {
        result = a;
        result->next = list_merge_sorted(a->next, b, cmp);
    } else {
        result = b;
        result->next = list_merge_sorted(a, b->next, cmp);
    }
    return result;
}

static void list_split(ListNode *source,
                       ListNode **front,
                       ListNode **back) {
    ListNode *slow = source;
    ListNode *fast = source->next;

    while (fast) {
        fast = fast->next;
        if (fast) {
            slow = slow->next;
            fast = fast->next;
        }
    }

    *front = source;
    *back = slow->next;
    slow->next = NULL;
}

ListNode *list_sort(
    ListNode *head,
    int (*cmp)(const void *, const void *)
) {
    if (!head || !head->next)
        return head;

    ListNode *a;
    ListNode *b;

    list_split(head, &a, &b);

    a = list_sort(a, cmp);
    b = list_sort(b, cmp);

    return list_merge_sorted(a, b, cmp);
}

void list_free(ListNode *list) {
    while (list) {
        ListNode *next = list->next;
        free(list);
        list = next;
    }
}