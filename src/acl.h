/**
 * @file acl.h
 * @author m4ghaniofficial@gmail.com
 * @brief This file define all functions which operate on ACL.
 * @version 0.1
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 */

#ifndef _ACL_H
#define _ACL_H

#include <arpa/inet.h>

enum ACL_DIRECTION {
	IN,
	OUT
};

enum RULE_ACCESSIBILITY {
	DENY,
	PERMIT
};

enum LOG {
	NO_LOG,
	YES_LOG
};

struct interface {
	enum ACL_DIRECTION acl_direction;
	char name[INET_ADDRSTRLEN];
};

struct acl_rule {
	enum RULE_ACCESSIBILITY accessibility;
	struct in_addr ip;
	int mask;
	enum LOG log;
};

struct acl_group {
	int acl_number;
	struct list_head *rule_head;
	struct list_head *intf_head;
};

int init_acl_head();

struct acl_group *search_group(int acl_number);
struct acl_rule *search_rule(int acl_number, struct in_addr ip);
struct interface *search_ifname(int acl_number, char *interface_name);

struct acl_group *new_acl(int acl_number);
int new_rule(int acl_number, struct in_addr ip, int mask,
              enum RULE_ACCESSIBILITY access, enum LOG log);
int add_rule(int acl_number, struct in_addr ip, int mask,
              enum RULE_ACCESSIBILITY access, enum LOG log);
int new_intf(int acl_number, char *interface_name,enum ACL_DIRECTION acl_direction);
int add_intf(int acl_number, char *interface_name,enum ACL_DIRECTION acl_direction);

int delete_interface(int acl_number, char *interface_name);
int delete_rule(int acl_number, struct in_addr ip);
int delete_group(int acl_number);

#endif
