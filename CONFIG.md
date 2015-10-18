# Configuration

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
--insert INPUT 3 RULES
--append INPUT RULES
RULES
"
```

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


  1. `i:INTERFACE` or `o:INTERFACE`

    Specify an interface matching, INTERFACE must be a interface name such as eth0, wlan0..
    If you want 'all interface', don't specify this setting

  2. IP ADDRESS
    * `d:IP/CIDR_MASK` or `dst:IP/CIDR_MASK` or `s:IP/CIDR_MASK` or `src:IP/CIDR_MASK`

      This command match for a specific ip, ip range, or ip network. The mask must be given in CIDR notation.
      The command `src` or `s` specify a source address and the command `dst` or `d` specify a destination address

  3. PROTOCOL

    * `tcp`

      Enable TCP protocol

    * `udp`

      Enable UDP protocol

    * `sp:PORT` or * `sp:PORT:PORT`

      This add a source port. Port can be a simple PORT or a port range as `PORT:PORT`

    * `dp:PORT` or * `dp:PORT:PORT`
    
      Add destination port or port range.

    * `icmp:TYPE`

      Apply to icmp protocol.
      The TYPE is optionnal and add supplementary match for icmp type

  4. MATCH

    * `c:TEXT` or `comment:TEXT`

      This add a comment into this rule.
      The TEXT does not contains any space

  5. OTHER
  
    * The script allow all other iptables command like in the manpage


* **COMMAND IPTABLES**

  If you want to full manually configure your firewall you can use the COMMANDS configuration string. These commands are run first, before all auto rules.
  In this field, just put the commands options, all words except the 'iptables' command name.

  The configuration variable is named COMMAND, the command are on one-per-line and can be put like this :

```bash
COMMANDS="
--table filter --protocol tcp

--append INPUT --match state


# this is a comment
"
```


* **SECURITY**

  The script try to provides some security feature with the firewall.
  The global boolean `IS_SECURITY_ENABLED` define if all security rules must be enabled

  1. DDOS

    The boolean `SECURITY_DDOS_RULES` enable or not the security rules about DDOS.
    The variable `DDOS_RULES` contains all anti DDOS rules.
    In this variable just put the rules. All of these will be prefix with the append command and put in the DDOS_PROTECT chain

  2. ICMP

    The boolean `SECURITY_ICMP_RULES` enable or not the security rules about ICMP.
    The variable `ICMP_RULES` contains all rules aim to protect against icmp attack.
    In this variable just put the rules. All of these will be prefix with the append command and put in the ICMP_PROTECT chain


* **OPTIONS**

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

  This variable is read by the service (init.d) script not by the main script (iptables-loader) because service management is Linux distribution dependent
