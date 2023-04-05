/**
 * @file acl.c
 * @author m4ghaniofficial@gmail.com
 * @brief This file generate all functions which operate on ACL.
 * @version 0.1
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 */

#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "functions.h"
#include "linked_list.h"
#include "acl.h"

struct list_head *acl_head;

int init_acl_head()
{
	acl_head = init_list();
	if (acl_head == NULL)
		return MEM_FAILED;
}

struct acl_group *search_group(int acl_number)
{
	struct node *node = acl_head->first_node;
	struct acl_group *group;
	while (node != NULL) {
		group = get_data(node);
		if (group->acl_number == acl_number)
			return group;
		node = node->next;
	}
	return NULL;
}

struct acl_rule *search_rule(int acl_number, struct in_addr ip)
{
	struct acl_group *group = search_group(acl_number);
	struct node *node;
	struct acl_rule *rule;
	if (group == NULL)
		return NULL;
	node = group->rule_head->first_node;
	while (node != NULL) {
		rule = get_data(node);
		if (rule->ip.s_addr == ip.s_addr)
			return rule;
		node = node->next;
	}
	return NULL;
}

struct interface *search_ifname(int acl_number, char *interface_name)
{
	struct acl_group *group = search_group(acl_number);
	struct node *node = group->intf_head->first_node;
	struct interface *intf;
	if (group == NULL)
		return NULL;
	while (node != NULL) {
		intf = get_data(node);
		if (!strncmp(intf->name, interface_name, sizeof(intf->name)))
			return intf;
		node = node->next;
	}
	return NULL;
}

struct acl_group *new_acl(int acl_number)
{
	struct acl_group *group;
	group =  malloc(sizeof(struct acl_group));
	if (group == NULL)
		return NULL;
	group->acl_number = acl_number;
	group->intf_head = init_list();
	group->rule_head = init_list();
	if (group->intf_head == NULL || group->rule_head == NULL)
		return NULL;
	if (add_node (acl_head, group) == MEM_FAILED)
		return NULL;
	return group;
}

int new_rule(int acl_number, struct in_addr ip, int mask,
              enum RULE_ACCESSIBILITY access, enum LOG log)
{
	struct acl_rule *rule;
	struct acl_group *group;

	group = search_group(acl_number);
	if (group == NULL) {
		group = new_acl(acl_number);
		if (group == NULL)
			return MEM_FAILED;
	}
	rule =  malloc(sizeof(struct acl_rule));
	if (rule == NULL)
		return MEM_FAILED;
	rule->ip = ip;
	rule->mask = mask;
	rule->accessibility = access;
	rule->log = log;

	if (add_node(group->rule_head, rule) == MEM_FAILED)
		return MEM_FAILED;
	return SUCCESS;
}

int add_rule(int acl_number, struct in_addr ip, int mask,
              enum RULE_ACCESSIBILITY access, enum LOG log)
{
	struct acl_rule *rule;

	rule = search_rule(acl_number, ip);
	if (rule == NULL) {
		if (new_rule(acl_number, ip, mask, access, log) == MEM_FAILED)
			return MEM_FAILED;
		return SUCCESS;
	} else {
		rule->ip = ip;
		rule->mask = mask;
		rule->accessibility = access;
		rule->log = log;
		return SUCCESS;
	}
}

int new_intf(int acl_number, char *interface_name,
              enum ACL_DIRECTION acl_direction)
{
	struct acl_group *group;
	struct interface *intf;
	group = search_group(acl_number);
	if (group == NULL)
		return ACL_NOT_FOUND;

	intf =  malloc(sizeof(struct interface));
	if (intf == NULL)
		return MEM_FAILED;
	strncpy(intf->name, interface_name, sizeof(intf->name));
	intf->acl_direction = acl_direction;

	if (add_node(group->intf_head, intf) == MEM_FAILED)
		return MEM_FAILED;
	return SUCCESS;
}

int add_intf(int acl_number, char *interface_name,
              enum ACL_DIRECTION acl_direction)
{
	int retval;
	struct interface *intf;
	intf = search_ifname(acl_number, interface_name);
	if (intf == NULL) {
		retval = new_intf(acl_number, interface_name, acl_direction);
		if (retval == MEM_FAILED)
			return MEM_FAILED;
		else if (retval == ACL_NOT_FOUND)
			return ACL_NOT_FOUND;
	} else {
		strncpy(intf->name, interface_name, sizeof(intf->name));
		intf->acl_direction = acl_direction;
		return SUCCESS;
	}
}

int delete_interface(int acl_number, char *interface_name)
{
	struct acl_group *group;
	struct interface *intf;
	struct node *tmp1;
	struct node *tmp2;
	struct node *node;

	group = search_group(acl_number);
	if (group == NULL)
		return ACL_NOT_FOUND;
	intf = search_ifname(acl_number, interface_name);
	if (intf == NULL)
		return INTF_NOT_FOUND;
	node = set_data(intf);
	tmp1 = group->intf_head->first_node;
	tmp2 = tmp1->next;
	if (tmp1->data == node->data) {
		if (delete_node(group->intf_head, node) == ACL_NOT_FOUND)
			return ACL_NOT_FOUND;
		return SUCCESS;
	}
	while (tmp1 != NULL) {
		if (tmp2->data == node->data) {
			tmp1->next = tmp2->next;
			if(delete_node(group->intf_head, node)== ACL_NOT_FOUND)
				return ACL_NOT_FOUND;
			return SUCCESS;
		}
		tmp1 = tmp1->next;
		tmp2 = tmp2->next;
	}
}

int delete_rule(int acl_number, struct in_addr ip)
{
	struct acl_group *group;
	struct acl_rule *rule;
	struct node *tmp1;
	struct node *tmp2;
	struct node *node;

	group = search_group(acl_number);
	if (group == NULL)
		return ACL_NOT_FOUND;
	rule = search_rule(acl_number, ip);
	if (rule == NULL)
		return ACL_NOT_FOUND;
	node = set_data(rule);
	tmp1 = group->rule_head->first_node;
	tmp2 = tmp1->next;
	if (tmp1->data == node->data) {
		if (delete_node(group->rule_head, node) == ACL_NOT_FOUND)
			return ACL_NOT_FOUND;
		return SUCCESS;
	}
	while (tmp1 != NULL) {
		if (tmp2->data == node->data) {
			tmp1->next = tmp2->next;
			if (delete_node(group->rule_head, node) == ACL_NOT_FOUND)
				return ACL_NOT_FOUND;
			return SUCCESS;
		}
		tmp1 = tmp1->next;
		tmp2 = tmp2->next;
	}
}

int delete_group(int acl_number)
{
	struct acl_group *group;
	struct node *tmp1;
	struct node *tmp2;
	struct node *node;

	group = search_group(acl_number);
	if (group == NULL)
		return ACL_NOT_FOUND;
	node = set_data(group);
	tmp1 = acl_head->first_node;
	tmp2 = tmp1->next;
	if (tmp1->data == node->data) {
		if (delete_node(acl_head, node) == ACL_NOT_FOUND)
			return ACL_NOT_FOUND;
		return SUCCESS;
	}
	while (tmp1 != NULL) {
		if (tmp2->data == node->data) {
			tmp1->next = tmp2->next;
			if (delete_node(acl_head, node) == ACL_NOT_FOUND)
				return ACL_NOT_FOUND;
			return SUCCESS;
		}
		tmp1 = tmp1->next;
		tmp2 = tmp2->next;
	}
}
