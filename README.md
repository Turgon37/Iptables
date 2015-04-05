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

  * **CHAINS**

The configuration file contains a shell variable for each chain name. 
For example the chain INPUT of FILTER table is configured in variable named :

>INPUT=""

The available list of chains is :
  INPUT FORWARD OUTPUT PREROUTING POSTROUTING

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

=> By default rules are inserted with the append method (are push to the end of the chain) if you want to specify this behaviour please specify the method in the begin of each rules like :

```bash
INPUT="
APPEND RULES
INSERT:2 RULES
INSERT:1 RULES
"
```
  1. `APPEND`
  
    The rule will be put after the last rules in the chain
  
  2. `INSERT:NUMBER`
  
    The rule will be put a the position specified by NUMBER (between 1 to number of rules)


  * **CHAINS**
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

  * **CHAINS**
    * **COMMAND**

  1. `INTERFACE:INTERFACE` or `INTERFACE`

    Specify an interface matching, INTERFACE must be a interface name such as eth0, wlan0.. or * to specify 'all interface'

    If you give only one interface name, it wiil be consider as input interface for input chains (INPUT, PREROUTING) and as output interface for output chains (OUTPUT, POSTROUTING)

    If you give the two interface name (including the * matching) the first name (at the left) will be consider as input interface and the second name (at the right) will be the output interface.

    If you use the FORWARD chain you must specify the two interface

  2. IP ADDRESS
    * `d:IP/CIDR_MASK` or `dst:IP/CIDR_MASK` or `s:IP/CIDR_MASK` or `src:IP/CIDR_MASK`

      This command match for a specific ip, ip range, or ip network. The mask must be given in CIDR notation.

      The command `src` or `s` specify a source address and the command `dst` or `d` specify a destination address

  3. PROTOCOL

    * `tcp:PORT` `tcp:PORT:PORT`    (PORT is PORT or PORT-PORT)

      Tcp match, the PORT can be a simple PORT or a port range as `PORT-PORT`.

      If only one port option is given it's the destination port, if the two are given the first (at the left) is the source and the other at the right is the destination

    * `udp:PORT` `udp:PORT:PORT`    (PORT is PORT or PORT-PORT)

      Udp match, same functionnality that TCP just above

    * `icmp:TYPE`

      Apply to icmp protocol.
      The TYPE is optionnal and add supplementary match for icmp type

  4. MATCH
    * `tcp:FLAG[,FLAG]:FLAG[,FLAG]`
      
      Define a tcp flag match. See the manual for more details
      
    * `tcp:syn` of * `tcp:SYN`
    
      Define a tcp syn flag match. See the manual for more details

    * `state:STATE`    (STATE can be STATE,STATE,STATE ...)

      Match packet by state, the state words can be all of these are defined in the iptables man page like RELATED,ESTABLISHED.
      You can put several state, they have to be separated by comma.

    * `c:TEXT` or `comment:TEXT`

      This add a comment into this rule.
      The TEXT does not contains any space

  5. ACTION

    * `j:ACTION` or `jump:ACTION`

      This set a simple action
      The ACTION can be ACCEPT, DROP, RETURN

    * `j:REJECT:CODE` or `jump:REJECT:CODE` 

      Set the REJECT action.
      The CODE is optionnal, and specify with which icmp code the reject must be executed.

    * `j:MASQUERADE` or `jump:MASQUERADE` 
    
      Set the MASQUERADE action, ONLY for NAT table


  * **COMMAND IPTABLES**

  Because the script cannot handle all iptables options a command string is providing to allow the user to put some manual iptables command. Theses command wiil be run by the script as automatics commands.
  
  The configuration variable is named COMMAND, the command are on one-per-line and can be put like this :
  
```bash
COMMANDS="
--table filter --protocol tcp 

--append INPUT --match state


# this is a comment
"
```


  * **CONFIGURATION**

  The rest of the configuration file must contains some global variable such as :


  1. IS_ROUTER [Boolean]

  Determine if the router mode is enabled. If True all forward rules will be loaded, if False there will not.

  2. DEFAULT_ACTION [String]

  Define the default iptables action when no j or jump parameter is given.
  Default to ACCEPT.

  3. TIMEOUT_FOR_TEST [Integer]

  The number of second to wait for reading the validating word during test script command



  * **SERVICE**

  The SERVICE variable must contains all service name you want to be restarted after the firewall restart.
  For example fail2ban need to use iptables to ban, and it must be restarted after flushing rules.

  This variable is read by the service script not by the main script because this function is distribution dependent



## Installation

### On debian installation

  1. Put the script into an appropriate folder and copy the service files from github init.d/ folder into your system /etc/init.d/ folder
  2. or simply install the provided deb package
    The service can be managed by /etc/init.d/iptables script or by the distribution available command such as ```service```

##### Requires:
  * A Debian based distribution


### In all installation

Put the script in a appropriate folder and write a system service script according to your booting manager if you want to run the firewall automatically at startup

##### Requires:
  * A Linux kernel > 2.4
  * The `iptables` command

  * xtables-addons to use some extra features