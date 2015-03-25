# Iptables

DEVELOPPMENT IN PROGRESS

This project is licensed under the terms of the MIT license

This is a shell script which provide a way to load iptables rules based on a configuration file.

It consists in a main script iptables.sh, which read a configuration file and load all iptables rules accordgin to this.

The main script is written to run as a service script

Currently the script is provided only for distributions based on Debian

## Usage

Run the script manually from it location like

```bash
  ./iptables COMMAND
```

Use the --help to show the full list of command

## Configuration

The default configuration file's location is in /etc/default/iptable
The configuration file consist in a simple shell script which contains only variable declaration because it is simply sourced at the iptables.sh startup.

  * **CHAINS**

The configuration file contains a shell variable for each chain name. For example the chain INPUT of FILTER table is configured in variable named :

>INPUT


To configure a chain you must to put a rules string in the corresponding variable defined below. For example, to set some rules into INPUT of FILTER table you have to type :

```bash
INPUT="RULES
RULES
RULES RULES

#_this_is_a_comment
"
```

=> All rules must be separated by at least a space or newline. the only condition is that all rules whose concerns a same chain in a table must be in the associated double quote (in other words must be in the shell variable)

=> Comments string with a sharp as the first caracter is allowed. **Please take care** that comment string are a **non space-separated** string. Because rules are space separated, a space in comment string will be intrepreted as a new rule

  * **RULES**
    * **FILTER**

Each rules in FILTER table have the following format : 

>COMMAND|COMMAND

They are composed of PIPE separated list of COMMAND



## Installation

### In debian installation

Put the script into an appropriate folder and copy the service files from github init.d/ folder into your system /etc/init.d/ folder
or simply install the provided deb package

##### Requires:
  * A Debian based distribution


### In all installation

Put the script in a appropriate folder

##### Requires:
  * A Linux kernel > 2.4
  * The iptables command

