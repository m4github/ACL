/**
 * @file functions.h
 * @author m4ghaniofficial@gmail.com
 * @brief This file define validations functions.
 * @version 0.1
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef _FUNCTIONS_H
#define _FUNCTIONS_H

#include <arpa/inet.h>

#define RULE_COMMAND_LEN   48
#define INTF_COMMAND_LEN   52

#define LIMIT_1         1
#define LIMIT_2         99
#define LIMIT_3         1300
#define LIMIT_4         1999

enum ERRORS {
	SUCCESS = 0,
	INVALID_IP,
	INVALID_NUMBER,
	INVALID_INTF,
	ACL_NOT_FOUND,
	INTF_NOT_FOUND,
	MEM_FAILED,
	INVALID_COMMAND,
	EXEC_FAIL,
	NUMERIC_FAILED,
	EXIT
};

enum VALIDATION {
	VALID,
	INVALID
};

void print_output(int retval);
int acl_number_validation(char *acl_number);
int interface_validation(char *name);
int ip_validation(char *ip);

int char_to_ip(char *ip, struct in_addr *des_ip);
int *ip_to_char(struct in_addr ip, char *str_ip);
int str_to_int(char *acl_number, int *i);

int fill_acl_rule_struct(char **token, int arg_counter);
int fill_if_direction_node(char **token, int arg_counter);
int delete_acl(char **token, int arg_counter);
int delete_intf(char **token, int arg_counter);

int show_acl();
int exit_program();

#endif
