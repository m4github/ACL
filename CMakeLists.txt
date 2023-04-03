cmake_minimum_required(VERSION 2.6)

project (acl)

set(SOURCES
     src/main.c
     src/acl.c
     src/functions.c
     src/linked_list.c
     src/decision.c
     src/iptables_generator.c
)

add_executable(main
    ${SOURCES}
)
