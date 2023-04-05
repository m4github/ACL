/**
 * @file decision.h
 * @author m4ghaniofficial@gmail.com
 * @brief This file define tokenize and decision functions. 
 * @version 0.2
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 */

#ifndef _DECISION_H
#define _DECISION_H

#define TOKEN_MAX_LEN 16
#define MAX_INPUT_LEN 63

#define COMPARE_EXIT_TOKEN(token)               !strncmp(token, "exit",       \
						 sizeof(token))
#define COMPARE_NO_TOKEN(token)                 !strncmp(token, "no",         \
						 sizeof(token))
#define COMPARE_ACL_TOKEN(token)                !strncmp(token, "access-list",\
						 sizeof(token))
#define COMPARE_ACCESS_TOKEN(token1,token2)     !strncmp(token1,"ip",         \
						 sizeof(token1)) &&  	      \
                                                        !strncmp(token2,      \
						"access-group", sizeof(token2))
#define COMPARE_SHOW_TOKEN(token1,token2)	!strncmp(token1,"show",       \
						sizeof(token1)) && 	      \
	                			 !strncmp(token2,	      \
						 "std-acl",sizeof(token2))

#define COMPARE_IF_TOKEN(token)      strncmp(token,"interface", sizeof(token))
#define COMPARE_LOG_TOKEN(token)     strncmp(token,"log",       sizeof(token))
#define COMPARE_PERMIT_TOKEN(token) !strncmp(token,"permit",    sizeof(token))
#define COMPARE_DENY_TOKEN(token)   !strncmp(token,"deny",      sizeof(token))						
#define COMPARE_IN_TOKEN(token)     !strncmp(token,"in",        sizeof(token))
#define COMPARE_OUT_TOKEN(token)    !strncmp(token,"out",       sizeof(token))
						
typedef int (*func_pointer)(char **, int arg_counter);
typedef func_pointer (*fun_ptr)();

int tokenize(char **token,char *sentence, int *arg_counter);

func_pointer decision(char **token,int arg_counter);

#endif
