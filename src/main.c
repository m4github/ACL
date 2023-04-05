/**
 * @file main.c
 * @author m4ghaniofficial@gmail.com
 * @brief main file start progress.
 * @version 0.2
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2021
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acl.h"
#include "decision.h"
#include "functions.h"

int main(int argc, char *argv[])
{
	int ret = 0;
	int arg_counter;
	func_pointer retval = NULL;
	char *input_command;
	char **token;
	size_t size;
	size = sizeof (input_command);

	input_command = (char *)malloc(MAX_INPUT_LEN);
	if (input_command == NULL)
		print_output(MEM_FAILED);

	if (init_acl_head() == MEM_FAILED)
		print_output(MEM_FAILED);

	token = malloc(MAX_INPUT_LEN);
	if (token == NULL)
		print_output(MEM_FAILED);

	while (1) {
		printf("\x1b[32m➜ \x1b[0m");
		getline(&input_command, &size, stdin);
		input_command[strlen(input_command) - 1] = '\0';

		arg_counter = 0; 
		if(tokenize(token,input_command, &arg_counter) == MEM_FAILED)
			print_output(MEM_FAILED);

		retval = decision(token,arg_counter);
		if (retval != NULL) {
			ret = retval (token,arg_counter);
			if (ret == EXIT) {
				free(token);
				free(input_command);
				exit(EXIT_SUCCESS);
			} else
				print_output(ret);

		} else
			print_output(INVALID_COMMAND);
	}
}
