/**
 * @file decision.c
 * @author m4ghaniofficial@gmail.com
 * @brief This file tokenize user input and decide the next step of program.
 * @version 0.2
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 */

#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "functions.h"
#include "decision.h"

int tokenize(char **token,char *sentence, int *arg_counter)
{
	char *token_tmp;
	int i = 0;
	token_tmp = strtok(sentence, " /");
	while (token_tmp != NULL) {
		token[i] = token_tmp;
		i++;
		*arg_counter = *arg_counter + 1;
		token_tmp = strtok(NULL, " /");
	}
	token[i] = NULL;
	return SUCCESS;
}

func_pointer decision(char **token, int arg_counter)
{
	if (token[0] == NULL)
		return NULL;

	if (COMPARE_EXIT_TOKEN(token[0]))
		return exit_program;


	else if (COMPARE_SHOW_TOKEN(token[0], token[1]))
		return show_acl;


	else if (COMPARE_NO_TOKEN(token[0])) {
		if (COMPARE_ACL_TOKEN(token[1]))
			return delete_acl;

		else if (COMPARE_ACCESS_TOKEN(token[1], token[2])) {
			if (!COMPARE_OUT_TOKEN(token[4])
			                || !COMPARE_IN_TOKEN(token[4]))
				if (COMPARE_IF_TOKEN(token[5]))
					return NULL;
			return delete_intf;
		}


	} else if (COMPARE_ACCESS_TOKEN(token[0], token[1])) {

		if (!COMPARE_IN_TOKEN(token[3]))
			if (!COMPARE_OUT_TOKEN(token[3]))
				return NULL;
		return fill_if_direction_node;


	} else if (COMPARE_ACL_TOKEN(token[0])) {

		if (!COMPARE_PERMIT_TOKEN(token[2]))
			if (!COMPARE_DENY_TOKEN(token[2]))
				return NULL;
		if (arg_counter > 5)
			if (COMPARE_LOG_TOKEN(token[5]))
				return NULL;
		return fill_acl_rule_struct;


	} else
		return NULL;
}
