//
// Created by owais on 1/21/2026.
//

#ifndef GSLIST_H
#define GSLIST_H

typedef struct ListNode {
    void *data;
    struct ListNode *next;
} ListNode;

#ifdef __cplusplus
extern "C" {
#endif

ListNode *list_prepend(ListNode *list, void *data);
static ListNode *list_merge_sorted(
    ListNode *a,
    ListNode *b,
    int (*cmp)(const void *, const void *)
);

static void list_split(ListNode *source,
                       ListNode **front,
                       ListNode **back);

ListNode *list_sort(
    ListNode *head,
    int (*cmp)(const void *, const void *)
);

    void list_free(ListNode *list);

#ifdef __cplusplus
}
#endif

#endif //GSLIST_H
