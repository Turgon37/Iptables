# Iptables

This project is licensed under the terms of the MIT license

This is a shell script which provide a way to load iptables rules based on a configuration file.

It consists in a main script iptables.sh, which read a configuration file and load all iptables rules according to this.

The main script is independant, if you want to load it as a system service (for example at boot time) you have to write a service script according to your distribution boot system (init, systemd ...)

## Usage

Run the script as root user manually from it location like

```bash
  ./iptables.sh COMMAND  
```

Use the `help` command to show the full list of command

## Configuration

The default configuration file's location is in /etc/default/iptables
The configuration file consists in a simple shell script which contains only variable declaration because it is simply sourced at the iptables.sh startup.

  1. **CHAINS**

The configuration file contains a shell variable for each chain name. 
For example the chain INPUT of FILTER table is configured in variable named :

>INPUT=""

To configure a chain you must to put a rules string in the corresponding variable defined below. For example, to set some rules into INPUT of FILTER table you have to type :

```bash
INPUT="RULES
RULES

RULES
RULES

# this is a comment
"
```

=> All rules must be separated by at least a newline. Each command on the same line are applied to the same rule

=> Comments string is allowed with a sharp as the first caracter.

  * **RULES**

Each RULES have the following format : 

>COMMAND COMMAND COMMAND

In the configuration file :

```bash
INPUT="
COMMAND COMMAND    COMMAND

COMMAND
COMMAND

# this is a comment
"
```

A list of space separated command whose concerns the same rule. Theses command are all OPTIONNAL, you can put just these you want

  * **COMMAND**
   
  
  1. `INTERFACE:INTERFACE` or `INTERFACE`
  
  Specify an interface matching, INTERFACE must be a interface name such as eth0, wlan0.. or * to specify 'all interface'
  
  If you give only one interface name, it wiil be consider as input interface for input chains (INPUT, PREROUTING) and as output interface for output chains (OUTPUT, POSTROUTING)
  
  If you give the two interface name (including the * matching) the first name (at the left) will be consider as input interface and the second name (at the right) will be the output interface.
  
  If you use the FORWARD chain you must specify the two interface
  
  2. `d:IP/CIDR_MASK` or `dst:IP/CIDR_MASK` or `s:IP/CIDR_MASK` or `src:IP/CIDR_MASK`
    
  This command match for a specific ip, ip range, or ip network. The mask must be given in CIDR notation.
  
  The command `src` or `s` specify a source address and the command `dst` or `d` specify a destination address
  

  3. `tcp:PORT` `tcp:PORT:PORT`    (PORT is PORT or PORT-PORT)
    
  Tcp match, the PORT can be a simple PORT or a port range as `PORT-PORT`.
  
  If only one port option is given it's the destination port, if the two are given the first (at the left) is the source and the other at the right is the destination

  4. `udp:PORT` `udp:PORT:PORT`    (PORT is PORT or PORT-PORT)
    
  Udp match, same functionnality that TCP just above
  
  5. `state:STATE`    (STATE can be STATE,STATE,STATE ...)
    
  Match packet by state, the state words can be all of these are defined in the iptables man page.

  * **COMMAND IPTABLE**
  
  Because the script cannot handle all iptables options a command string is providing to allow the user to put some manual iptables command. Theses command wiil be run by the script as automatics commands.
  
  The configuration variable is named COMMAND, the command are on one-per-line and can be put like this :
  
```bash
COMMANDS="
--table filter --protocol tcp 

--append INPUT --match state


# this is a comment
"
```
    

## Installation

### On debian installation

  1. Put the script into an appropriate folder and copy the service files from github init.d/ folder into your system /etc/init.d/ folder
  2. or simply install the provided deb package

##### Requires:
  * A Debian based distribution


### In all installation

Put the script in a appropriate folder and write a system service script according to your booting manager if you want to run the firewall automatically at startup

##### Requires:
  * A Linux kernel > 2.4
  * The `iptables` command
  
  * The new `ip` command if you want to use 
  * xtables-addons to use some extra features
  

