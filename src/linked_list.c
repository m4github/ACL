/**
 * @file linked_list.c
 * @author m4ghaniofficial@gmail.com
 * @brief This file do all activities about generic linked list.
 * @version 0.1
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "linked_list.h"
#include "functions.h"

struct list_head *init_list()
{
	struct list_head *head;
	head =  malloc(sizeof(struct list_head));
	if (head == NULL)
		return NULL;
	head->first_node = NULL;
	head->count = 0;
	return head;
}

int add_node(struct list_head *head,void *data)
{
	struct node *node;
	node =  malloc(sizeof(struct node));
	if (node == NULL)
		return MEM_FAILED;
	node->data = data;
	node->next = head->first_node;
	head->first_node = node;
	head->count++;

	return SUCCESS;
}

int delete_node(struct list_head *head, struct node *node)
{
	if (head->first_node == NULL){
		return ACL_NOT_FOUND;
	}else if(head->first_node->data == node->data){ 
			head->first_node = node->next;
			free(node->data);
			free(node);
			return SUCCESS;
	}else{
		free(node->data);
		free(node);
		return SUCCESS;
	}
}

void *get_data(struct node *node)
{
	if (node == NULL)
		return NULL;
	return node->data;
}

struct node *set_data(void *info)
{
	struct node *node = malloc(sizeof(struct node));
	node->data = info;
	node->next = NULL;
	return node;
}

void free_list(struct list_head *head)
{
	struct node *node;

	if(head->first_node == NULL)
		return;
		
	while (head->first_node != NULL) {
		node = head->first_node;
		head->first_node = node->next;
		free(node->data);
		free(node);
	}
}
