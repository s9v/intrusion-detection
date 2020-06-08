#pragma once
#include <assert.h>
#include <stdlib.h>

//struct hole_node;

struct hnode {
    int first;
    int last;
    struct hnode *prev;
    struct hnode *next;
};

void hlist_init(struct hnode *list_head) {
    list_head->prev = NULL;
    list_head->next = NULL;
}

struct hnode *hlist_delete(struct hnode *node) {
    assert(node != NULL);

    if (node->prev == NULL) // can't delete head
        return node;

    if (node->next != NULL)
        node->next->prev = node->prev;
    node->prev->next = node->next;

    struct hnode *next = node->next;
    free(node);
    return next;
}

struct hnode *hlist_new(int first, int last) {
    struct hnode *new_node = malloc(sizeof(struct hnode));

    new_node->first = first;
    new_node->last = last;
    new_node->prev = NULL;
    new_node->next = NULL;

    return new_node;
}

struct hnode *hlist_insert(struct hnode *after, struct hnode *new_node) {
    assert(after != NULL);
    assert(new_node != NULL);

    new_node->next = after->next;
    new_node->prev = after;

    if (after->next != NULL)
        after->next->prev = new_node;
    after->next = new_node;
}

