# ACL
    tiny ACL implementation by @forghani_m

# Build and Debug
    mkdir build
    cd build
    cmake ..
    cmake --build .

# Usage
Use below command to start the program:

    ./main
        

ACL-number range = 

    [1-99],[1300-1999]


# Commands
Add new rule.

    access-list access-list-number {permit|deny} {source/mask} [log]

Apply iptables-rules to an interface.

    ip access-group number {in|out} interface <interface>

Delete all rules in a access-list.

    no access-list access-list-number

Add "no" to the beggining of acl commands to delete that command.


List all ACL commands on program.

    show std-acl
    
Exit the program.

    exit
