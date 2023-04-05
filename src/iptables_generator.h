/**
 * @file iptables_generator.h
 * @author m4ghaniofficial@gmail.com
 * @brief This file define iptables generation functions.
 * @version 0.1
 * @date 2022-01-24
 *
 * @copyright Copyright (c) 2022
 */

#ifndef _IPTABLES_GENERATOR_H
#define _IPTABLES_GENERATOR_H

#define COMMAND_SECTIONS 10
    
int execution(char *command[]);
int iptables_apply(void);

#endif
