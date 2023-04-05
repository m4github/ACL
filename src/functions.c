/**
 * @file functions.c
 * @author m4ghaniofficial@gmail.com
 * @brief In this file all activities that are needed for ACL get start and validations are here too.
 * @version 0.1
 * @date 2022-02-02
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "acl.h"
#include "decision.h"
#include "functions.h"
#include "linked_list.h"
#include "iptables_generator.h"

extern struct list_head *acl_head;

void print_output(int retval)
{
	switch(retval) {
	case INVALID_IP:
		fprintf(stderr, "\e[31mInvalid IP/mask.\x1b[0m\n");
		break;
	case INVALID_INTF:
		fprintf(stderr, "\e[31mInvalid interface.\x1b[0m\n");
		break;
	case INVALID_NUMBER:
		fprintf(stderr, "\e[31mInvalid ACL number.\x1b[0m\n");
		break;
	case INVALID_COMMAND:
		fprintf(stderr, "\e[31mInvalid command.\x1b[0m\n");
		break;
	case EXEC_FAIL:
		fprintf(stderr, "\e[31mFailed to run command.\x1b[0m\n");
		break;
	case ACL_NOT_FOUND:
		fprintf(stderr, "\e[31mACL not found.\x1b[0m\n");
		break;
	case INTF_NOT_FOUND:
		fprintf(stderr, "\e[31mInterface not found.\x1b[0m\n");
		break;
	case MEM_FAILED:
		fprintf(stderr, "Couldn't allocate memory\n");
		break;
	case NUMERIC_FAILED:
		fprintf(stderr, "\e[31mFailed to scan acl number.\x1b[0m\n");
		break;
	default:
		break;
	}
}

int acl_number_validation(char *acl_number)
{
	int numeric;
	if (str_to_int (acl_number, &numeric) != SUCCESS)
		return EXEC_FAIL;

	if ((numeric >= LIMIT_1 && numeric <= LIMIT_2)
	                || (numeric >= LIMIT_3 && numeric <= LIMIT_4))
		return VALID;
	return INVALID;
}

int interface_validation(char *name)
{
	struct ifaddrs *ifname ;
	int retval = INVALID;
	if (getifaddrs(&ifname) == -1)
		return EXEC_FAIL;
	while (ifname) {
		if (!strncmp(ifname->ifa_name, name, sizeof (ifname->ifa_name)))
			retval = VALID;
		ifname = ifname->ifa_next;
	}
	freeifaddrs(ifname);
	return retval;
}

int ip_validation(char *ip)
{
	struct in_addr des_ip;
	int retval = VALID;
	if (inet_pton(AF_INET, ip, &des_ip) == 0)
		retval = INVALID;
	else if (inet_pton(AF_INET, ip, &des_ip) == -1)
		retval = EXEC_FAIL;
	return retval;
}

int char_to_ip(char *ip, struct in_addr *des_ip)
{
	if (inet_pton(AF_INET, ip, des_ip) != 1)
		return EXEC_FAIL;
}

int *ip_to_char(struct in_addr ip, char *str_ip)
{
	if (inet_ntop(AF_INET, &ip, str_ip, INET_ADDRSTRLEN) == NULL)
		return NULL;
	return SUCCESS;
}

int str_to_int(char *acl_number, int *i)
{
	if (sscanf(acl_number, "%i", i) != 1)
		return EXEC_FAIL;
	return SUCCESS;
}

int fill_acl_rule_struct(char **token, int arg_counter)
{
	enum LOG log = NO_LOG;
	enum RULE_ACCESSIBILITY access;
	int acl_number;
	int retval;
	struct in_addr ip;
	int mask;

	retval = acl_number_validation(token[1]);
	if (retval == INVALID)
		return INVALID_NUMBER;
	else if (retval == EXEC_FAIL)
		return NUMERIC_FAILED;

	retval = ip_validation(token[3]);
	if (retval == INVALID)
		return INVALID_IP;
	else if (retval == EXEC_FAIL)
		return EXEC_FAIL;

	if (str_to_int(token[1], &acl_number) != SUCCESS)
		return NUMERIC_FAILED;

	if (COMPARE_PERMIT_TOKEN(token[2]))
		access = PERMIT;
	else if (COMPARE_DENY_TOKEN(token[2]))
		access = DENY;

	if(char_to_ip(token[3], &ip) == EXEC_FAIL)
		return EXEC_FAIL;

	if(str_to_int(token[4], &mask) != SUCCESS)
		return EXEC_FAIL;

	if (arg_counter > 5)
		log = YES_LOG;
	if (add_rule(acl_number, ip, mask, access, log) == MEM_FAILED)
		return MEM_FAILED;
	return SUCCESS;
}

int fill_if_direction_node(char **token, int arg_counter)
{
	enum ACL_DIRECTION acl_direction;
	int acl_number;
	int retval;

	retval = acl_number_validation(token[2]);
	if (retval == INVALID)
		return INVALID_NUMBER;
	else if (retval == EXEC_FAIL)
		return NUMERIC_FAILED;

	retval = interface_validation(token[5]);
	if (retval == INVALID)
		return INVALID_INTF;
	else if (retval == EXEC_FAIL)
		return EXEC_FAIL;

	if (str_to_int(token[2], &acl_number) != SUCCESS)
		return NUMERIC_FAILED;
	if (COMPARE_IN_TOKEN(token[3]))
		acl_direction = IN;
	else if (COMPARE_OUT_TOKEN(token[3]))
		acl_direction = OUT;

	if (search_group(acl_number) == NULL)
		return ACL_NOT_FOUND;
	else {
		if (add_intf(acl_number, token[5], acl_direction) == MEM_FAILED)
			return MEM_FAILED;
		retval = iptables_apply();
		return retval;
	}
}

int delete_acl(char **token, int arg_counter)
{
	int acl_number;
	int retval;
	struct in_addr ip;

	retval = acl_number_validation(token[2]);
	if (retval == INVALID)
		return INVALID_NUMBER;
	else if (retval == EXEC_FAIL)
		return NUMERIC_FAILED;

	if (str_to_int(token[2], &acl_number) != SUCCESS)
		return NUMERIC_FAILED;

	if (arg_counter < 4) {
		if (delete_group(acl_number) == ACL_NOT_FOUND)
			return ACL_NOT_FOUND;
		else
			return SUCCESS;
	} else {
		retval = ip_validation(token[3]);
		if (retval == INVALID)
			return INVALID_IP;
		else if (retval == EXEC_FAIL)
			return EXEC_FAIL;

		if(char_to_ip(token[3], &ip) == EXEC_FAIL)
			return EXEC_FAIL;

		if (delete_rule(acl_number, ip) == ACL_NOT_FOUND)
			return ACL_NOT_FOUND;
		else
			return SUCCESS;
	}
}

int delete_intf(char **token, int arg_counter)
{
	int retval;
	int acl_number;
	struct in_addr ip;

	retval = acl_number_validation(token[3]);
	if (retval == INVALID)
		return INVALID_NUMBER;
	else if (retval == EXEC_FAIL)
		return NUMERIC_FAILED;

	if (str_to_int(token[3], &acl_number) != SUCCESS)
		return NUMERIC_FAILED;

	retval = delete_interface(acl_number, token[5]);
	if (retval == ACL_NOT_FOUND)
		return ACL_NOT_FOUND;
	else if (retval == INTF_NOT_FOUND)
		return INTF_NOT_FOUND;

	else
		return iptables_apply();
}

int show_acl()
{
	char *rule_output[6], *intf_output[6];
	char str_ip[INET_ADDRSTRLEN+3];
	char acl_number_str[5],mask_str[3];
	struct acl_group *group;
	struct acl_rule *rule;
	struct interface *intf;

	struct node *group_node = acl_head->first_node;
	struct node *rule_node, *intf_node;

	while (group_node != NULL) {
		group = get_data(group_node);
		if (group == NULL)
			return ACL_NOT_FOUND;
		rule_node = group->rule_head->first_node;
		intf_node = group->intf_head->first_node;

		while (rule_node != NULL) {
			rule = get_data(rule_node);
			if (rule == NULL)
				return ACL_NOT_FOUND;
			rule_output[0] = "access-list ";
				sprintf(acl_number_str, "%d", group->acl_number);
			rule_output[1] = acl_number_str;
			rule_output[2] = (rule->accessibility == PERMIT) ? " permit " :" deny ";

			if (ip_to_char(rule->ip, str_ip) != SUCCESS)
				return EXEC_FAIL;
			sprintf(mask_str, "%d", rule->mask);
			strcat	(str_ip,"/");
			strcat	(str_ip,mask_str);
			rule_output[3]=str_ip;

			if (rule->log == YES_LOG){
				rule_output[4]="log";
				rule_output[5]=NULL;
			}else{
				rule_output[4]=NULL;
				rule_output[5]=NULL;
			}
			for(int i=0;rule_output[i]; i++)
				fprintf(stdout, "%s", rule_output[i]);
			printf("\n");

			rule_node = rule_node->next;
		
		}
		while (intf_node != NULL) {
			intf = get_data(intf_node);

			if (intf == NULL)
				return INTF_NOT_FOUND;
			intf_output[0] = "ip access-group ";
			intf_output[1] = acl_number_str;
			intf_output[2] = (intf->acl_direction == OUT) ? " out" : " in";
			intf_output[3] = " interface";
			intf_output[4] = intf->name;        
			intf_output[5] = NULL;

			for(int i=0;intf_output[i]; i++)
				fprintf(stdout, "%s", intf_output[i]);
			printf("\n");

			intf_node = intf_node->next;
		} 
		group_node = group_node->next;
	}
	return SUCCESS;
}

int exit_program()
{
	struct node *group_node;
	struct acl_group *group;

	if (acl_head->first_node == NULL)
		return EXIT;

	group_node = acl_head->first_node;
	while (group_node != NULL) {
		group = get_data(group_node);
		free_list(group->intf_head);
		free_list(group->rule_head);
		group_node = group_node->next;
	}
	free_list(acl_head);
	return EXIT;
}
