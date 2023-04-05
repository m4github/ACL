/**
 * @file iptables_generator.c
 * @author m4ghaniofficial@gmail.com
 * @brief In this file iptables command generated and execute on system.
 * @version 0.1
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 */

#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "linked_list.h"
#include "acl.h"
#include "functions.h"
#include "iptables_generator.h"

extern struct list_head *acl_head;

int iptables_apply(void)
{
	char *iptables_command[COMMAND_SECTIONS];
	char *flush_iptables[3] = {"/sbin/iptables", "-F", NULL};
	char mask_str[3], str_ip[INET_ADDRSTRLEN+3];
	int flush_status;
	pid_t flush_pid;

	int iptable_status;
	pid_t iptable_pid;

	struct acl_group *group;
	struct acl_rule *rule;
	struct interface *intf;
	struct node *group_node = acl_head->first_node;
	struct node *rule_node, *intf_node;

	if (group_node == NULL)
		return ACL_NOT_FOUND;

	flush_pid = fork();

	if (flush_pid < 0)
		return EXEC_FAIL;
	else if (flush_pid == 0) {
		execvp(flush_iptables[0], flush_iptables);
		return (EXEC_FAIL);
	} else
		wait4(flush_pid, &flush_status, 0, NULL);

	while (group_node != NULL) {
		group = get_data(group_node);
		if (group == NULL)
			return ACL_NOT_FOUND;
		rule_node = group->rule_head->first_node;
		intf_node = group->intf_head->first_node;

		while (rule_node != NULL) {
			rule = get_data(rule_node);

			iptables_command[0] = "/sbin/iptables";
			iptables_command[1] = "-A";
			iptables_command[2] = "FORWARD";
			iptables_command[5] = "-s";

			if (ip_to_char(rule->ip, str_ip) != SUCCESS)
				return EXEC_FAIL;
			sprintf(mask_str, "%d", rule->mask);

			strcat	(str_ip,"/");
			strcat	(str_ip,mask_str);
			iptables_command[6] = str_ip;
			iptables_command[7] = "-j";
			iptables_command[8] = (rule->accessibility == PERMIT) ? "ACCEPT" : "DROP";
			iptables_command[9] = NULL;

			while (intf_node != NULL) {
				intf = get_data(intf_node);
				iptables_command[3] = (intf->acl_direction == IN) ? "-i" : "-o";
				iptables_command[4] = intf->name;

				iptable_pid = fork();

				if (iptable_pid < 0)
					return EXEC_FAIL;
				else if (iptable_pid == 0) {
					execvp(iptables_command[0], iptables_command) ;
					return (EXEC_FAIL);
				} else
					wait4(iptable_pid, &iptable_status, 0, NULL);

				intf_node = intf_node->next;
			}
			rule_node = rule_node->next;
		}
		group_node = group_node->next;
	}
	return SUCCESS;
}
