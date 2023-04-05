/**
 * @file linked_list.h
 * @author m4ghaniofficial@gmail.com
 * @brief This file define generic linked list and its functions.
 * @version 0.1
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 */

#ifndef _LINKED_LIST_H
#define _LINKED_LIST_H

struct node {
	void *data;
	struct node *next;
};

struct list_head {
	struct node *first_node;
	int count;
};

struct list_head *init_list();
int add_node(struct list_head *head, void *data);
void *get_data(struct node *node);
struct node *set_data(void *info);
int delete_node(struct list_head *head, struct node *node);
void free_list(struct list_head *head);

#endif
