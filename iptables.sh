#!/bin/bash
#title         :iptables
#description   :Configure rules for iptables firewall
#author        :P.GINDRAUD
#author_contact:pgindraud@gmail.com
#created_on    :2014-05-30
#usage         :./iptables <CMD>
#usage_info    :use command 'help'
#options       :debug
#notes         :
# During the development process, please take a real care to report all errors,
# and don't worry about using debug option to control the good running of the
# script
#versions_notes:
# version 1.0
#    +first release
# version 2.0 : 2014-09-23
#    +re parsing of all rules
#    -remove return_state variables
#    +fix iptables error
# version 2.1 : 2014-09-24
#    +add missing _do_restart function
#    +correct functions syntax
#    +fix bug of test function
#    +add a verbose warning message
# version 2.2 : 2014-10-26
#    +add a new configuration file /etc/default/iptables
#    +set routing rules by a loop for configuration file
# version 3.0 : 2015-03-25
#    +refunding main loop and core processing, full dynamic loading
#
VERSION='3.0'
#==============================================================================

#========== INTERNAL OPTIONS ==========#
IPTABLES="dump"
IP6TABLES=$(which ip6tables)
#IPTABLES_CONFIG=/etc/default/iptables
IPTABLES_CONFIG=./config

IPTABLES_BACKUP_FILE=/etc/iptables.backup

# The field separator caracter
F_SEP='|'
# The key => config separator
C_SEP=':'


#========== INTERNAL VARIABLES ==========#
IS_DEBUG=0
IS_VERBOSE=0

## WORKING REGEX
# Don't touch unless you know what you are doing
# all regex whose begin with E_ prefix are wrote in extended regex language
# REGEX that describe a IFACE name
REG_IFACE='\([a-zA-Z*][a-zA-Z0-9*]*+\?\)'
E_REG_IFACE='([a-zA-Z*][a-zA-Z0-9*]*+?)'

# REGEX that describe a network ipv4 address
REG_IPV4='\(\(\([0-9]\|[1-9][0-9]\|1[0-9]\{2\}\|2[0-4][0-9]\|25[0-5]\).\)\{3\}\([0-9]\|[1-9][0-9]\|1[0-9]\{2\}\|2[0-4][0-9]\|25[0-5]\)\(/\([0-9]\|[12][0-9]\|3[0-2]\)\)\?\)'
E_REG_IPV4='((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(/([0-9]|[12][0-9]|3[0-2]))?)'

# REGEX that describe a port number (between 1 and 65535)
REG_PORT='\([0-9]\{1,4\}\|[1-5][0-9]\{4\}\|6[0-4][0-9]\{3\}\|65[0-4][0-9]\{2\}\|655[0-2][0-9]\|6553[0-5]\)'
E_REG_PORT='([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'

# REGEX that describe a port range like PORT-PORT (use this for port matching)
REG_RANGE="\(${REG_PORT}\(-${REG_PORT}\)\?\)"
E_REG_RANGE="(${E_REG_PORT}(-${E_REG_PORT})?)"

# REGEX that describe a layer 4 protocol
REG_PROTO='\(tcp\|udp\)'
E_REG_PROTO='(tcp|udp)'

# REGEX that describe the source addr
REG_SRC='\(s\|src\)'
E_REG_SRC='(s|src)'

# REGEX that describe the destination addr
REG_DST='\(d\|dst\)'
E_REG_DST='(d|dst)'


#========== INTERNAL FUNCTIONS ==========#

function dump() {
  return
}


# Print a msg to stdout if verbose option is set
# @param[string] : the msg to write in stdout
function _echo() {
  if [ $IS_VERBOSE -eq 1 ]; then
    echo -e "$@"
  fi
}

# Print a msg to stderr if verbose option is set
# @param[string] : the msg to write in stderr
function _error() {
  if [ $IS_VERBOSE -eq 1 ]; then
    echo -e "Error : $@" 1>&2
  fi
}

# Print a msg to stdout if debug verbose is set
# @param[string] : the msg to write in stdout
function _debug() {
  if [ $IS_DEBUG -eq 1 ]; then
    echo -e "debug: $@"
  fi
}

# Check if the script is run by root or not. If not, prompt error and exit
function _isRunAsRoot() {
  if [ "$(id -u)" != "0" ]; then
    log_failure_msg "$DESC: This script must be run as root."
    exit 1
  fi
}


#========== PROGRAM FUNCTIONS ==========#

## PARSING CONFIG
# Retrieve the procotol string from a input string
# @param[string] : the input string
function parseProtocol() {
  expr match "$1" "$REG_PROTO:.*"
}

# Retrieve the source port (range) when this is the only parameter given
# @param[string] : the input string
function parsePortDstOnly() {
  str=$(expr match "$1" ".*:$REG_RANGE")
  echo -n ${str//-/:}
}

# Retrieve the source port (range) string from a input string
# @param[string] : the input string
function parsePortSrc() {
  str=$(expr match "$1" ".*:$REG_RANGE:.*")
  echo -n ${str//-/:}
}

# Retrieve the destination port (range) string from a input string
# @param[string] : the input string
function parsePortDst() {
  str=$(expr match "$1" ".*:.*:$REG_RANGE")
  echo -n ${str//-/:}
}

# Retrieve the ipv4 address from a input string
# @param[string] : the input string
function parseAddress() {
  expr match "$1" ".*:$REG_IPV4"
}

# Retrieve the input iface name string from a input string
# @param[string] : the input string
function parseIfaceInput() {
  expr match "$1" "$REG_IFACE"
}

# Retrieve the output iface name string from a input string
# @param[string] : the input string
function parseIfaceOutput() {
  expr match "$1" ".*:$REG_IFACE"
}


### ---
### RULES MGMT
### ---
# Remove all rules in all chains
function _flush_rules() {
  $IPTABLES --table filter --flush
  $IPTABLES --table nat --flush
  $IPTABLES --table mangle --flush
}
# Remove all user defined chains (these what are not built in)
function _flush_chains() {
  $IPTABLES --table filter --delete-chain
  $IPTABLES --table nat --delete-chain
  $IPTABLES --table mangle --delete-chain
}
# Reset all packets counter
function _reset_counters() {
  $IPTABLES --table filter --zero
  $IPTABLES --table nat --zero
  $IPTABLES --table mangle --zero
}


### ---
### GLOBAL POLICIES
### ---
# Set policy to open, no security
# @param[string] : the policy type in 'accept', 'drop'
function _policy {
  if [ "$1" = 'accept' ]; then
    # FILTER
    $IPTABLES --table filter --policy INPUT ACCEPT
    $IPTABLES --table filter --policy OUTPUT ACCEPT

    if [ $IF_IPV4_FORWARD -eq 1 ]; then
      $IPTABLES --table filter -P FORWARD ACCEPT
    else
      $IPTABLES --table filter -P FORWARD DROP
    fi

    # NAT
    $IPTABLES --table nat --policy PREROUTING ACCEPT
    $IPTABLES --table nat --policy OUTPUT ACCEPT
    $IPTABLES --table nat --policy INPUT ACCEPT
    $IPTABLES --table nat --policy POSTROUTING ACCEPT
  elif [ "$1" = 'drop' ]; then
    # FILTER
    $IPTABLES --table filter --policy INPUT DROP
    $IPTABLES --table filter --policy OUTPUT DROP

    $IPTABLES --table filter --policy FORWARD DROP
  fi
}

### ---
### GLOBAL RULES LOADING
### ---
# Load network rules
# @param[string] : the name of the table in which to load the rules
#        INPUT OUTPUT FORWARD
# @param[string] : the configuration string from configuration file
# @return[int] : 0 if all rule are correctly set
#                X  the iptables return code
#                100 if an input rule is declare with a output interface
#                101 if an output rule is declare with a input interface
#                102 if a single interface is given for FORWARD table
#                103 if the table name is not in INPUT, OUTPUT, FORWARD
function _load_filter_rules() {
  # bad table name
  if [[ ! $1 =~ ^INPUT|OUTPUT|FORWARD$ ]]; then
    return 103
  fi
  # Loop for each rule (separated by space)
  for entry in $2; do
    _debug "reading config entry : $entry"
    local protocol=
    local src_port=
    local dst_port=
    local src_address=
    local dst_address=
    local in_iface=
    local out_iface=
    # Loop for each command (separated by F_SEP, pipe as default)
    for c in ${entry//${F_SEP}/ }; do
      # PARTIAL PORT (dst only) matching
      if [[ "$c" =~ ^${E_REG_PROTO}${C_SEP}${E_REG_RANGE}$ ]]; then
        _debug "  => proto+port : $c"
        protocol=$(parseProtocol "$c")
        if [[ -n $protocol ]]; then
          protocol="--protocol $protocol"
        fi
        dst_port=$(parsePortDstOnly "$c")
        if [[ -n $dst_port ]]; then
          dst_port="--destination-port $dst_port"
        fi
      # FULL PORT (dst+src) matching
      elif [[ "$c" =~ ^${E_REG_PROTO}${C_SEP}${E_REG_RANGE}${C_SEP}${E_REG_RANGE}$ ]]; then
        _debug "  => proto+port+port : $c"
        protocol=$(parseProtocol "$c")
        if [[ -n $protocol ]]; then
          protocol="--protocol $protocol"
        fi
        src_port=$(parsePortSrc "$c")
        if [[ -n $src_port ]]; then
          src_port="--source-port $src_port"
        fi
        dst_port=$(parsePortDst "$c")
        if [[ -n $dst_port ]]; then
          dst_port="--destination-port $dst_port"
        fi
      # SOURCE ADDRESS matching
      elif [[ "$c" =~ ^${E_REG_SRC}${C_SEP}${E_REG_IPV4}$ ]]; then
        _debug "  => src addr : $c"
        src_address=$(parseAddress "$c")
        if [[ -n $src_address && $src_address != '*' ]]; then
          src_address="--source $src_address"
        else
          src_address=
        fi
      # DESTINATION ADDRESS matching
      elif [[ "$c" =~ ^${E_REG_DST}${C_SEP}${E_REG_IPV4}$ ]]; then
        _debug "  => dst addr : $c"
        dst_address=$(parseAddress "$c")
        if [[ -n $dst_address && $dst_address != '*' ]]; then
          dst_address="--destination $dst_address"
        else
          dst_address=
        fi
      # SINGLE INTERFACE matching
      elif [[ "$c" =~ ^${E_REG_IFACE}$ ]]; then
        _debug "  => iface : $c"
        
        # interface
        iface=$(parseIfaceInput "$c")
        if [[ -n $iface ]]; then
          # error during forward rule with an unique interface
          if [[ $1 = 'FORWARD' ]]; then
            _error "single interface in FORWARD table (ambiguous rules) '$entry'"
            return 102
          elif [[ "$1" = 'INPUT' ]]; then
            in_iface="--in-interface $iface"
          elif [[ "$1" = 'OUTPUT' ]]; then
            out_iface="--out-interface $iface"
          fi
        else
          in_iface=
          out_iface=
        fi  
      
      # IN/OUT INTERFACE matching
      elif [[ "$c" =~ ^${E_REG_IFACE}${C_SEP}${E_REG_IFACE}$ ]]; then
        _debug "  => iface+iface : $c"
        
        # input interface
        in_iface=$(parseIfaceInput "$c")
        if [[ -n $in_iface ]]; then
          # error during output rule with an input interface
          if [[ $1 = 'OUTPUT' ]]; then
            _error "input interface in OUTPUT table '$entry'"
            return 101
          fi
          in_iface="--in-interface $in_iface"
        else
          in_iface=
        fi
        
        # output interface
        out_iface=$(parseIfaceOutput "$c")
        if [[ -n $out_iface && $out_iface != '*' ]]; then
          # error during input rule with an output interface
          if [[ $1 = 'INPUT' ]]; then
            _error "output interface in INPUT table '$entry'"
            return 100
          fi
          out_iface="--out-interface $out_iface"
        else
          out_iface=
        fi
      else
        _error "error reading line : $entry"
      fi
    done
    _echo --table filter --append $1 $in_iface $out_iface $src_address $dst_address $protocol $src_port $dst_port
    $IPTABLES --table filter --append $1 $in_iface $out_iface $src_address $dst_address $protocol $src_port $dst_port
    result=$?
    if [[ $result -ne 0 ]]; then
      return $result
    fi
  done
  return 0
}


function _load_anti_ddos_rules() {
  $IPTABLES --table filter --new-chain DDOS_PROTECT
  
}



###### RUNNING ######
IS_VERBOSE=1

# Load global configuration
[[ -r $IPTABLES_CONFIG ]] && source $IPTABLES_CONFIG

# Exit if the iptables command is not available
if [[ ! -x "$IPTABLES" ]]; then
  _error "The iptables command is the path or not installed"
   #exit 1
fi

# Exit if the config have not been sourced
if [[ -z "$IF_CONFIG_SOURCED" ]]; then
  _error "The configuration file have not been source or is not readable"
  #exit 2
fi




_load_filter_rules 'INPUT' "$INPUT"
result=$?
if [[ $? -ne 0 ]]; then exit $?; fi
_load_filter_rules 'OUTPUT' "$OUTPUT"
result=$?
if [[ $? -ne 0 ]]; then exit $?; fi
_load_filter_rules 'FORWARD' "$FORWARD"
result=$?
if [[ $? -ne 0 ]]; then exit $?; fi



exit 
###############################
###############################
# DO NOT READ UNDER THIS LINE #
###############################
###############################














#========== MAIN FUNCTION ==========#
# Main
# param	:same of the script
# return	:
function main() {
  _check_runas_root

  ### ARGUMENTS PARSING
  case "$1" in
  start)
    log_daemon_msg "Setting firewall rules. Enable firewall secure policy" "$NAME"
    do_start 2> /dev/null
    case $? in
    0|1) log_end_msg 0;;
    *) log_end_msg 1
      log_failure_msg "$DESC: Failed to start the firewall."
      ;;
    esac
    ;;
  stop)
    log_daemon_msg "Removing firewall rules. Turn firewall to open policy" "$NAME"
    do_stop 2>/dev/null
    case $? in
    0|1)	log_end_msg 0;;
    *) log_end_msg 1
      log_failure_msg "$DESC: Failed to stop the firewall."
      ;;
    esac
    ;;
  restart)
    log_daemon_msg "Re-setting firewall rules" "$NAME"
    do_restart 2>/dev/null
    case $? in
    # restart success
    0|1)	log_end_msg 0;;
    # start failed
    2)	log_end_msg 1
      log_failure_msg "$DESC: Failed to start the firewall."
      ;;
    # stop failed
    3)	log_end_msg 1
      log_failure_msg "$DESC: Failed to stop the firewall."
      ;;
    esac
    ;;
  restore)
    log_daemon_msg "Loading firewall rules from ${IPTABLES_BACKUP_FILE}" "$NAME"
    do_restore 2>/dev/null
    case "$?" in
    0|1) log_end_msg 0 ;;
    *) log_end_msg 1 ;;
    esac
    ;;
  test)
    log_action_msg "Testing new firewall rulesets" "$NAME"
    do_test 2>/dev/null
    ;;
  *)
    echo "Usage: $SCRIPTNAME {start|stop|restart|save|restore|test}" >&2
    exit 3
    ;;
  esac
}

main "$@"





































### ---
### PACKETS
### ---
# Set specific rules which concerns packet
function _set_packet_rules() {
  # Drop broadcast paquets
  $IPTABLES -A INPUT -m pkttype --pkt-type broadcast -j DROP
}



### ---
### INTERFACE
### ---
function _allow_loopback_interface() {
# Allow loopback interface
  $IPTABLES -t filter -A INPUT -i lo --source ${NETWORK_LOOPBACK} --destination ${NETWORK_LOOPBACK} -j ACCEPT
  $IPTABLES -t filter -A OUTPUT -o lo --source ${NETWORK_LOOPBACK} --destination ${NETWORK_LOOPBACK} -j ACCEPT
}



### ---
### CONNECTION STATE
### ---
function _allow_connection_state() {
# Keep established connections
  if [ -n "$NETWORK_ETH0" ]; then
    $IPTABLES -A INPUT -i eth0 --destination ${NETWORK_ETH0} -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPTABLES -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  if [ -n "$NETWORK_WLAN0" ]; then
    $IPTABLES -A INPUT -i wlan0 --source ${NETWORK_WLAN0} --destination ${NETWORK_WLAN0} -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPTABLES -A OUTPUT -o wlan0 --source ${NETWORK_WLAN0} --destination ${NETWORK_WLAN0} -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  if [ -n "$NETWORK_VPN" ]; then
    $IPTABLES -A INPUT -i tun0 --source ${NETWORK_VPN} --destination ${NETWORK_VPN} -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPTABLES -A OUTPUT -o tun0 --source ${NETWORK_VPN} --destination ${NETWORK_VPN} -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  if [ -n "$NETWORK_ETH0_ALT" ]; then
    $IPTABLES -A INPUT -i eth0 --source ${NETWORK_ETH0_ALT} --destination ${HOST_LOCAL_ALT} -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPTABLES -A OUTPUT -o eth0 --source ${HOST_LOCAL_ALT} --destination ${NETWORK_ETH0_ALT} -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi

  if [ $IF_IPV4_FORWARD -eq 1 ]; then
    $IPTABLES -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
  fi
}

function _setup_nat_masquerading() {
  if [ -n "$NETWORK_VPN" ]; then
    $IPTABLES -t nat -A POSTROUTING -o eth0 --source ${NETWORK_VPN} -j MASQUERADE -m comment --comment "Masquerade connection from VPN network to eth0"
  fi
}


### ---
### PROTOCOLE ICMP
### ---
# Set the rules for allow icmp input output
function _allow_input_output_icmp() {
# ICMP [In,Out]
if [ -n "$NETWORK_ETH0" ]; then
  $IPTABLES -t filter -A INPUT -i eth0 --source ${NETWORK_ETH0} --destination ${NETWORK_ETH0} -p icmp -j ACCEPT -m comment --comment "Allow PING in for eth0 network"
  $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p icmp -j ACCEPT -m comment --comment "Allow PING out from eth0"
fi

if [ -n "$NETWORK_WLAN0" ]; then
  $IPTABLES -t filter -A INPUT -i wlan0 --source ${NETWORK_WLAN0} --destination ${NETWORK_WLAN0} -p icmp -j ACCEPT -m comment --comment "Allow PING in for wlan0 network"
  $IPTABLES -t filter -A OUTPUT -o wlan0 --source ${NETWORK_WLAN0} --destination ${NETWORK_WLAN0} -p icmp -j ACCEPT -m comment --comment "Allow PING out from wlan0"
fi

if [ -n "$NETWORK_VPN" ]; then
  $IPTABLES -t filter -A INPUT -i tun0 --source ${NETWORK_VPN} --destination ${NETWORK_VPN} -p icmp -j ACCEPT -m comment --comment "Allow PING in for vpn network"
  $IPTABLES -t filter -A OUTPUT -o tun0 --source ${NETWORK_VPN} --destination ${NETWORK_VPN} -p icmp -j ACCEPT -m comment --comment "Allow PING out from vpn network"
fi
}

# Set the rules for icmp packets routing
function _allow_routing_icmp() {
# ICMP [Forward]
  $IPTABLES -t filter -A FORWARD -p icmp -j ACCEPT -m comment --comment "Allow ICMP routing"
}





### ---
### SERVICES
### ---
# Set the rules for input or output connections



## ALL
function _allow_input_output_service_for_all() {
# WakeOnLan AND Wol Relayd[In,Out]
  if [ -n "${WOLRELAYD_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -p udp --dport ${WOLRELAYD_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow Wake On Lan relay in"
    $IPTABLES -t filter -A OUTPUT -p udp --dport ${WOLRELAYD_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow Wake On Lan out"
  fi

# DHCP server [In,Out]
  $IPTABLES -t filter -A INPUT -p udp --sport 68 --dport 67 -j ACCEPT -m comment --comment "Allow DHCP server in from all"
  $IPTABLES -t filter -A OUTPUT -p udp --sport 67 --dport 68 -j ACCEPT -m comment --comment "Allow DHCP server out from all"
}



## %%%%%%%%%%%%%%%%%  ETH0  %%%%%%%%%%%%%%%%%
function _allow_input_output_service_for_eth0() {

# SSH [In,Out]
  if [ -n "${SSHD_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i eth0 --destination ${NETWORK_ETH0} -p tcp --dport ${SSHD_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow SSH in for eth0"
    $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p tcp --dport 22 -j ACCEPT -m comment --comment "Allow SSH out from eth0"
  fi

# WHOIS []
  #$IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p tcp --dport 43 -j ACCEPT -m comment --comment "Allow WHOIS lookup from eth0"

# SMTP [In]
  $IPTABLES -t filter -A INPUT -i eth0 --source ${NETWORK_ETH0} --destination ${NETWORK_ETH0} -p tcp --dport 25 -j ACCEPT -m comment --comment "Allow SMTP in for eth0"

# DNS [In,Out]
  if [ -n "${BIND_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i eth0 --source ${NETWORK_ETH0} --destination ${NETWORK_ETH0} -p udp --dport ${BIND_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow DNS in for eth0"
    $IPTABLES -t filter -A INPUT -i eth0 --source ${NETWORK_ETH0} --destination ${NETWORK_ETH0} -p tcp --dport ${BIND_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow DNS in for eth0"
  fi

  $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p udp --dport 53 -j ACCEPT -m comment --comment "Allow DNS out from eth0"
  $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p tcp --dport 53 -j ACCEPT -m comment --comment "Allow DNS out from eth0"

# DHCP client []
  #$IPTABLES -t filter -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT -m comment --comment "Allow DHCP client out from all"

# HTTP [Out]
#	$IPTABLES -t filter -A INPUT -i eth0 --destination ${NETWORK_ETH0} -p tcp --dport 80 -j ACCEPT -m comment --comment "Allow HTTP in for eth0"
  $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p tcp --dport 80 -j ACCEPT -m comment --comment "Allow HTTP out from eth0"

# NTP [Out]
  $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p udp --dport 123 -j ACCEPT -m comment --comment "Allow NTP out from eth0"

# Https [Out]
  $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p tcp --dport 443 -j ACCEPT -m comment --comment "Allow HTTPs out from eth0"

# Microsoft-ds/Cifs [Out]
  if [ -n "${CIFS_PORT}" ]; then
    $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} --destination ${NETWORK_ETH0} -p tcp --dport ${CIFS_PORT} -j ACCEPT -m comment --comment "Allow Microsoft-ds/CIFS out from eth0 for lan"
  fi

# Smtps []
  #$IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p tcp --dport 465 -j ACCEPT -m comment --comment "Allow SMTPs out from eth0"

# Syslog [In]
  if [ -n "${SYSLOG_REMOTE_HOSTS}" ]; then
    $IPTABLES -t filter -A INPUT -i eth0 --source "${SYSLOG_REMOTE_HOST}" --destination ${NETWORK_ETH0} -p udp --dport 514 -j ACCEPT -m comment --comment "Allow Remote Syslog entries in for eth0"
    $IPTABLES -t filter -A INPUT -i eth0 --source "${SYSLOG_REMOTE_HOST}" --destination ${NETWORK_ETH0} -p tcp --dport 514 -j ACCEPT -m comment --comment "Allow Remote Syslog entries in for eth0"
  fi

# Submission [Out]
  if [ -n "${POSTFIX_RELAYHOST_ADDRESS}" ]; then
    $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} --destination ${POSTFIX_RELAYHOST_ADDRESS} -p tcp --dport 587 -j ACCEPT -m comment --comment "Allow Authentified SMTP (Submission) out from eth0"
  fi

# OpenVPN [In]
  if [ -n "${OPENVPN_LISTEN_PORT}" ] && [ -n "${OPENVPN_LISTEN_PROTOCOL}" ]; then
    $IPTABLES -t filter -A INPUT -i eth0 --destination ${NETWORK_ETH0} -p ${OPENVPN_LISTEN_PROTOCOL} --dport ${OPENVPN_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow VPN in for eth0"
  fi

# Minissdpd []
  #$IPTABLES -t filter -A INPUT -i eth0 --destination ${NETWORK_ETH0} -p udp --dport 1900 -j ACCEPT -m comment --comment "Allow SSDP in for eth0"

# Mysql [In]
  if [ -n "${MYSQL_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i eth0 --source ${NETWORK_ETH0} --destination ${NETWORK_ETH0} -p tcp --dport ${MYSQL_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow MySQL in for eth0"
  fi

# ShellInABox [In]
  if [ -n "${SHELLINABOX_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i eth0 --destination ${NETWORK_ETH0} -p tcp --dport ${SHELLINABOX_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow WebSSH ShellInABox in for eth0"
  fi

# NAT-PMP []
  #$IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p udp --dport 5351 -j ACCEPT -m comment --comment "Allow NAT-PMP out from eth0"

# Transmission torrent control panel [In]
  if [ -n "${TRANSMISSION_RPC_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i eth0 --source ${NETWORK_ETH0} --destination ${NETWORK_ETH0} -p tcp --dport ${TRANSMISSION_RPC_LISTEN_PORT} -j ACCEPT  -m comment --comment "Allow Transmission Remote Web Panel in for eth0"
  fi

# Git [Out]
  $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p tcp --dport 9418 -j ACCEPT -m comment --comment "Allow Git out from eth0"

# Transmission torrent peer [In,Out]
  if [ -n "${TRANSMISSION_PEER_LISTEN_PORT}" ] && [ -n "${TRANSMISSION_USERNAME}" ]; then
    $IPTABLES -t filter -A INPUT -i eth0 --destination ${NETWORK_ETH0} -p udp --dport ${TRANSMISSION_PEER_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow Transmission Torrent peer listen for eth0"
    $IPTABLES -t filter -A INPUT -i eth0 --destination ${NETWORK_ETH0} -p tcp --dport ${TRANSMISSION_PEER_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow Transmission Torrent peer listen for eth0"

    $IPTABLES -t filter -A OUTPUT -o eth0 --source ${NETWORK_ETH0} -p tcp -m owner --uid-owner ${TRANSMISSION_USERNAME} -j ACCEPT -m comment --comment "Allow Transmission Torrent data upload for SYSTEM USER ${TRANSMISSION_USERNAME}"
  fi
}



## %%%%%%%%%%%%%%%%%  WLAN0  %%%%%%%%%%%%%%%%%
function _allow_input_output_service_for_wlan0() {

# SSH [In]
  if [ -n "${SSHD_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i wlan0 --source ${NETWORK_WLAN0} --destination ${NETWORK_WLAN0} -p tcp --dport ${SSHD_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow SSH in for wlan0"
  fi

# DNS [In]
  if [ -n "${BIND_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i wlan0 --source ${NETWORK_WLAN0} --destination ${NETWORK_WLAN0} -p udp --dport ${BIND_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow DNS in for wlan0"
    $IPTABLES -t filter -A INPUT -i wlan0 --source ${NETWORK_WLAN0} --destination ${NETWORK_WLAN0} -p tcp --dport ${BIND_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow DNS in for wlan0"
  fi

# HTTP [In]
#	$IPTABLES -t filter -A INPUT -i wlan0 --destination ${NETWORK_WLAN0} -p tcp --dport 80 -j ACCEPT -m comment --comment "Allow HTTP in for wlan0"

# Transmission torrent control panel [In]
  if [ -n "${TRANSMISSION_RPC_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i wlan0 --source ${NETWORK_WLAN0} --destination ${NETWORK_WLAN0} -p tcp --dport ${TRANSMISSION_RPC_LISTEN_PORT} -j ACCEPT  -m comment --comment "Allow Transmission Remote Web Panel in for wlan0"
  fi
}



## %%%%%%%%%%%%%%%%%  TUN0 (vpn)  %%%%%%%%%%%%%%%%%
function _allow_input_output_service_for_vpn() {

# SSH [In]
if [ -n "${SSHD_LISTEN_PORT}" ]; then
  $IPTABLES -t filter -A INPUT -i tun0 --source ${NETWORK_VPN} --destination ${NETWORK_VPN} -p tcp --dport ${SSHD_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow SSH in for VPN"
fi

# DNS [In]
  if [ -n "${BIND_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i tun0 --source ${NETWORK_VPN} --destination ${NETWORK_VPN} -p udp --dport ${BIND_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow DNS in for VPN"
    $IPTABLES -t filter -A INPUT -i tun0 --source ${NETWORK_VPN} --destination ${NETWORK_VPN} -p tcp --dport ${BIND_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow DNS in for VPN"
  fi

# HTTP [In]
#	$IPTABLES -t filter -A INPUT -i tun0 --destination ${NETWORK_VPN} -p tcp --dport 80 -j ACCEPT -m comment --comment "Allow HTTP in for VPN"

# Transmission torrent control panel [In]
  if [ -n "${TRANSMISSION_RPC_LISTEN_PORT}" ]; then
    $IPTABLES -t filter -A INPUT -i tun0 --source ${NETWORK_VPN} --destination ${NETWORK_VPN} -p tcp --dport ${TRANSMISSION_RPC_LISTEN_PORT} -j ACCEPT  -m comment --comment "Allow Transmission Remote Web Panel in for VPN"
  fi
}



## %%%%%%%%%%%%%%%%% ETH0:0  %%%%%%%%%%%%%%%%%
function _allow_input_output_service_for_eth0_0() {

# SSH [In]
if [ -n "${SSHD_LISTEN_PORT}" ]; then
  $IPTABLES -t filter -A INPUT -i eth0 --source ${NETWORK_ETH0_ALT} --destination ${HOST_LOCAL_ALT} -p tcp --dport ${SSHD_LISTEN_PORT} -j ACCEPT -m comment --comment "Allow SSH in for eth0-ALT"
fi
}





# Set rule for service packets routing
function _allow_routing_service() {
  # ignore empty and commented lines
  local forwardedPort=$(echo "$FORWARDED_PORT" | grep --invert-match --regexp='#' --regexp='^$')
  # count the number of rules
  local nbLine=$(echo "$forwardedPort" | wc -l)

  for i in `seq $nbLine`; do
    line=$(echo "$forwardedPort" | head -n $i | tail -n1)

    # get comment informations
    if [ -n "$(echo $line | grep 'comment/')" ]; then
      local comment_opts=$(echo $line | sed -E 's/^.*(comment)\/("[-_A-Za-z ]+").*/-m comment --comment/')
      local comment_text=$(echo $line | sed -E 's/^.*comment\/"([-_A-Za-z ]+)".*/\1/')
    fi

    local port_opts=$(echo $line | sed -E 's/^(tcp|udp)\/([0-9:]+).*/-p \1 --dport \2/')
    # apply rule
    $IPTABLES -t filter -A FORWARD $port_opts -j ACCEPT $comment_opts "$comment_text"
  done
}




####### GARBAGE

# HTTP + HTTPS Out
#$IPTABLES -t filter -A OUTPUT -p tcp --dport 80 -j ACCEPT
#$IPTABLES -t filter -A OUTPUT -p tcp --dport 443 -j ACCEPT

# HTTP + HTTPS In
#$IPTABLES -t filter -A INPUT -p tcp --dport 80 -j ACCEPT
#$IPTABLES -t filter -A INPUT -p tcp --dport 443 -j ACCEPT
#$IPTABLES -t filter -A INPUT -p tcp --dport 8443 -j ACCEPT

# FTP Out
#$IPTABLES -t filter -A OUTPUT -p tcp --dport 20:21 -j ACCEPT

# FTP In
#modprobe ip_conntrack_ftp # ligne facultative avec les serveurs OVH
#$IPTABLES -t filter -A INPUT -p tcp --dport 20:21 -j ACCEPT
#$IPTABLES -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Mail SMTP:25
#$IPTABLES -t filter -A INPUT -p tcp --dport 25 -j ACCEPT
#$IPTABLES -t filter -A OUTPUT -p tcp --dport 25 -j ACCEPT

# Mail POP3:110
#$IPTABLES -t filter -A INPUT -p tcp --dport 110 -j ACCEPT
#$IPTABLES -t filter -A OUTPUT -p tcp --dport 110 -j ACCEPT

# Mail IMAP:143
#$IPTABLES -t filter -A INPUT -p tcp --dport 143 -j ACCEPT
#$IPTABLES -t filter -A OUTPUT -p tcp --dport 143 -j ACCEPT

# Mail POP3S:995
#$IPTABLES -t filter -A INPUT -p tcp --dport 995 -j ACCEPT
#$IPTABLES -t filter -A OUTPUT -p tcp --dport 995 -j ACCEPT