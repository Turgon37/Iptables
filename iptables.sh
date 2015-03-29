#!/bin/bash
#title         :iptables
#description   :Configure rules for iptables firewall
#author        :P.GINDRAUD, T.PAJON
#author_contact:pgindraud@gmail.com,th.pajon45@gmail.com
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
# version 3.0 : 2015-03-29
#    +refunding main loop and core processing, full dynamic loading
#
readonly VERSION='3.0'
#==============================================================================
INPUT=
OUTPUT=
FORWARD=
PREROUTING=
POSTROUTING=
COMMANDS=
SERVICES=
IS_ROUTER=0
DEFAULT_ACTION=ACCEPT
TIMEOUT_FOR_TEST=9


#========== INTERNAL OPTIONS ==========#
readonly IPTABLES=$(which iptables 2>/dev/null)
readonly IP6TABLES=$(which ip6tables 2>/dev/null)

readonly IPTABLES_CONFIG=/etc/default/iptables

readonly IPTABLES_BACKUP_FILE=/etc/iptables.backup

# The key => config separator
readonly C_SEP=':'


#========== INTERNAL VARIABLES ==========#
IS_DEBUG=0
IS_VERBOSE=0

readonly DEFAULT_IFS=$IFS
## WORKING REGEX
# Don't touch unless you know what you are doing
# all regex whose begin with E_ prefix are wrote in extended regex language
# REGEX that describe a string thaht must not be present in all configuration string, this regexp must be an only | characters alternatives
readonly E_REG_FORBID='(\;)'

# REGEX that describe a IFACE name
readonly REG_IFACE='\([a-zA-Z*][a-zA-Z0-9*]*+\?\)'
readonly E_REG_IFACE='([a-zA-Z*][a-zA-Z0-9*]*\+?)'

# REGEX that describe a network ipv4 address
readonly REG_IPV4='\(\(\([0-9]\|[1-9][0-9]\|1[0-9]\{2\}\|2[0-4][0-9]\|25[0-5]\).\)\{3\}\([0-9]\|[1-9][0-9]\|1[0-9]\{2\}\|2[0-4][0-9]\|25[0-5]\)\(/\([0-9]\|[12][0-9]\|3[0-2]\)\)\?\)'
readonly E_REG_IPV4='((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[12][0-9]|3[0-2]))?)'

# REGEX that describe a port number (between 1 and 65535)
readonly REG_PORT='\([0-9]\{1,4\}\|[1-5][0-9]\{4\}\|6[0-4][0-9]\{3\}\|65[0-4][0-9]\{2\}\|655[0-2][0-9]\|6553[0-5]\)'
readonly E_REG_PORT='([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'

# REGEX that describe a port range like PORT-PORT (use this for port matching)
readonly REG_RANGE="\(${REG_PORT}\(-${REG_PORT}\)\?\)"
readonly E_REG_RANGE="(${E_REG_PORT}(-${E_REG_PORT})?)"

# REGEX that qualify a network which has a gateway
readonly E_REG_GW="(${C_SEP}gw)"

#REGEX that describe a connection state
readonly E_REG_STATE="(INVALID|ESTABLISHED|NEW|RELATED|UNTRACKED)"
readonly REG_STATE="\(INVALID\|ESTABLISHED\|NEW\|RELATED\|UNTRACKED\)"


#========== INTERNAL FUNCTIONS ==========#

function dump() {
  return
}


# Print help msg
function _usage() {
  echo -e "Usage : $0 [OPTION...] COMMAND

An iptables bash loader script

Version : $VERSION

Command :
  start     load the firewall rules into kernel
  stop      unload and flush all rules from firewall
  restart   reload all rules (use after configuration editing)
  list      list all current iptables rules
  save      save all rules in a file
  restore   restore all rules from a file
  test      test command : provide a test procedure to reload
              new rules after configuration editing. Fi the new rules
              cause a connection break the old rules are automatically
              replaced
  help      show this help message

Options :
  -v, --verbose   Show more running messages 
  -d, --debug     Show debug messages
  
Return code :
  0     Success
  1-98  Reserved for iptables error code
  99    Unknown error
  100   Error input rules with a output interface
  101   Error output rules with a input interface
  102   Single interface in a forward rule
  105   Incorrect character in configuration file
  106   Incorrect numeric value for a variable
  107   Incorrect string value for a variable
  200   Need to be root
  201   Bad system arguments
  202   Missing COMMAND in shell args
  203   Missing a system needed program
  204   Unable to load configuration file
  205   Missing restore fileecho
  206   'test' command fail, new rules cause a break of connection
"
}

# Print a msg to stdout if verbose option is set
# @param[string] : the msg to write in stdout
function _echo() {
  if [[ $IS_VERBOSE -eq 1 ]]; then
    echo -e "$@"
  fi
}

# Print a msg to stderr if verbose option is set
# @param[string] : the msg to write in stderr
function _error() {
  if [[ $IS_VERBOSE -eq 1 ]]; then
    echo -e "Error : $@" 1>&2
  fi
}

# Print a msg to stdout if debug verbose is set
# @param[string] : the msg to write in stdout
function _debug() {
  if [[ $IS_DEBUG -eq 1 ]]; then
    echo -e "debug: $@"
  fi
}

# Check if the script is run by root or not. If not, prompt error and exit
function _isRunAsRoot() {
  if [[ "$UID" != "0" ]]; then
    _error "This script must be run as root."
    exit 200
  fi
}

# Check if an option is set to a 'true' value or not
# @param[string] : value to check
# @return[int] : 0 if value is consider as true
#                1 if not
function _isTrue() {
  [[ "$1" =~ ^(true|TRUE|True|1)$ ]]
}

#========== PROGRAM FUNCTIONS ==========#
# Retrieve the ipv4 address from a input string
# @param[string] : the input string
# @param[string] OPTIONNAL : the REGEX prefix
# @param[string] OPTIONNAL : the REGEX suffix
function parseAddress4() {
  expr match "$1" "${2}${REG_IPV4}${3}"
}

# Retrieve the iface name string from a input string
# @param[string] : the input string
# @param[string] OPTIONNAL : the REGEX prefix
# @param[string] OPTIONNAL : the REGEX suffix
function parseIface() {
  expr match "$1" "${2}${REG_IFACE}${3}"
}

# Return the list of availables interfaces
# @return[string] : the list of availables interfaces
function ifacesList() {
  ip link show | awk -F': ' '/^[0-9]*:/{print $2}' | awk -F'\n' '{if ($1 ~ /'$E_REG_IFACE'/) print $1}'
}


### ---
### TABLES MGMT
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
  if [[ "$1" = 'accept' ]]; then
    _debug 'setting policy to accept'
    # FILTER
    $IPTABLES --table filter --policy INPUT ACCEPT
    $IPTABLES --table filter --policy OUTPUT ACCEPT

    if _isTrue $IS_ROUTER; then
      $IPTABLES --table filter --policy FORWARD ACCEPT
    else
      $IPTABLES --table filter --policy FORWARD DROP
    fi

    # NAT
    $IPTABLES --table nat --policy PREROUTING ACCEPT
    $IPTABLES --table nat --policy OUTPUT ACCEPT
    $IPTABLES --table nat --policy INPUT ACCEPT
    $IPTABLES --table nat --policy POSTROUTING ACCEPT
  elif [[ "$1" = 'drop' ]]; then
    _debug 'setting policy to drop'
    # FILTER
    $IPTABLES --table filter --policy INPUT DROP
    $IPTABLES --table filter --policy OUTPUT DROP

    $IPTABLES --table filter --policy FORWARD DROP
  else
    _error 'Undefined global policy'
  fi
}



function _load_anti_ddos_rules() {
  $IPTABLES --table filter --new-chain DDOS_PROTECT
  
}


### ---
### GLOBAL RULES LOADING
### ---
# Load network rules
# @param[string] : the name of the chain in which to load the rules
# @param[string] : the configuration string from configuration file
# @param[string] OPTIONNAL : the table name in which include new rules
# @return[int] : 0 if all rule are correctly set
#                X  the iptables return code
#                100 if an input rule is declare with a output interface
#                101 if an output rule is declare with a input interface
#                102 if a single interface is given for FORWARD table
#                105 a incorrect character have been found in given list of command
function _load_rules() {
  local chain=$1
  local table=$3
  if [[ -z $table ]]; then
    table=filter
  fi
  
  if [[ "$2" =~ $E_REG_FORBID ]]; then
    _error 'An forbidden character is found'
    return 105
  fi
  _debug "# entering _load_filter_rules : $1"
  # set the internal field separator to newline only
  IFS=$'\n'
  # Loop for each rule (separated by space)
  for entry in $2; do
    _debug "reading config entry : $entry"
    # if a sharp is found drop this line, it's a comment line
    if [[ ${entry:0:1} = "#" ]]; then
      _debug "  => comment : $entry"
      continue
    fi
    local src_address=
    local dst_address=
    local in_iface=
    local out_iface=
    local protocol_opt=
    local match_opt=
    local action_opt=
    IFS=$DEFAULT_IFS
    # Loop for each command (separated by F_SEP, pipe as default)
    for c in $entry; do
      local match=
      local protocol=
      local action=
      # SOURCE ADDRESS matching
      if [[ "$c" =~ ^(s|src)${C_SEP}${E_REG_IPV4}$ ]]; then
        _debug "  => src addr : $c"
        src_address=$(parseAddress4 "$c" '.*'${C_SEP})
        if [[ -n $src_address && $src_address != '*' ]]; then
          src_address="--source $src_address"
        else
          src_address=
        fi
      # DESTINATION ADDRESS matching
      elif [[ "$c" =~ ^(d|dst)${C_SEP}${E_REG_IPV4}$ ]]; then
        _debug "  => dst addr : $c"
        dst_address=$(parseAddress4 "$c" '.*'${C_SEP})
        if [[ -n $dst_address && $dst_address != '*' ]]; then
          dst_address="--destination $dst_address"
        else
          dst_address=
        fi
      # PROTOCOL matching
      elif _protocol "$c"; then
        protocol_opt="$protocol_opt $protocol"
      # MATCH matching
      elif _match "$c"; then
        match_opt="$match_opt $match"
      # ACTION matching
      elif _action "$c"; then
        action_opt="$action_opt $action"
      # SINGLE INTERFACE matching
      elif [[ "$c" =~ ^${E_REG_IFACE}$ ]]; then
        _debug "  => iface : $c"
        # interface
        iface=$(parseIface "$c")
        if [[ -n $iface ]]; then
          # error during forward rule with an unique interface
          if [[ $1 = 'FORWARD' ]]; then
            _error "single interface in $chain chain (ambiguous rules) '$entry'"
            return 102
          elif [[ "$1" =~ INPUT|PREROUTING ]]; then
            in_iface="--in-interface $iface"
          elif [[ "$1" =~ OUTPUT|POSTROUTING ]]; then
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
        in_iface=$(parseIface "$c")
        if [[ -n $in_iface && $in_iface != '*' ]]; then
          # error during output rule with an input interface
          if [[ $1 =~ OUTPUT|POSTROUTING ]]; then
            _error "input interface in $chain chain '$entry'"
            return 101
          fi
          in_iface="--in-interface $in_iface"
        else
          in_iface=
        fi
        
        # output interface
        out_iface=$(parseIface "$c" '.*'${C_SEP})
        if [[ -n $out_iface && $out_iface != '*' ]]; then
          # error during input rule with an output interface
          if [[ $1 =~ INPUT|PREROUTING ]]; then
            _error "output interface in $chain chain '$entry'"
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
    # NO ACTION => default action
    if [[ -z $action_opt ]]; then
      action_opt="--jump $DEFAULT_ACTION"
    fi
    $IPTABLES --table $table --append $1 $in_iface $out_iface $src_address $dst_address $protocol_opt $match_opt $action_opt
    local r=$?
    if [[ $r -ne 0 ]]; then
      _error 'An error appear during the last command'
      return $r
    fi
    IFS=$'\n'
  done
  # reset the internal field separator for 'for' loop
  IFS=$DEFAULT_IFS
  return 0
}

# Parse protocol rules
# @param[string] : the input string in which search for matching rules
# @return[int] : 0 if a match success and the match command is returned in 'protocol' shell variable
#                1 if no match is performed
function _protocol() {
  _debug "  reading protocol entry : $1"
  
  # TCP matching
  if [[ "$1" =~ ^tcp(${C_SEP}${E_REG_RANGE}(${C_SEP}${E_REG_RANGE})?)?$ ]]; then
    _debug "    => proto tcp : $1"
    local src_port=$(expr match "$1" "tcp${C_SEP}${REG_RANGE}")
    local dst_port=$(expr match "$1" "tcp${C_SEP}.+${C_SEP}${REG_RANGE}")
    # full port matching (source and destination)
    if [[ -n $src_port && -n $dst_port ]]; then
      src_port="--source-port ${src_port//-/:}"
      dst_port="--destination-port ${dst_port//-/:}"
    # partial port matching (only destination)
    elif [[ -n $src_port ]]; then
      dst_port="--destination-port ${src_port//-/:}"
      src_port=
    fi
    
    protocol="--protocol tcp $src_port $dst_port"
    return 0
  # UDP matching
  elif [[ "$1" =~ ^udp(${C_SEP}${E_REG_RANGE}(${C_SEP}${E_REG_RANGE})?)?$ ]]; then
    _debug "    => proto udp : $1"
    local src_port=$(expr match "$1" "udp${C_SEP}${REG_RANGE}")
    local dst_port=$(expr match "$1" "udp${C_SEP}.+${C_SEP}${REG_RANGE}")
    # full port matching (source and destination)
    if [[ -n $src_port && -n $dst_port ]]; then
      src_port="--source-port ${src_port//-/:}"
      dst_port="--destination-port ${dst_port//-/:}"
    # partial port matching (only destination)
    elif [[ -n $src_port ]]; then
      dst_port="--destination-port ${src_port//-/:}"
      src_port=
    fi
  
    protocol="--protocol udp $src_port $dst_port"
    return 0
  # ICMP matching
  elif [[ "$1" =~ ^icmp(${C_SEP}[-a-zA-Z0-9/]+)?$ ]]; then
    _debug "    => proto icmp : $1"
    local type=$(expr match "$1" ".*${C_SEP}\([-a-zA-Z0-9/]\+\)")
    if [[ -n $type ]]; then
      type="--icmp-type $type"
    fi
    protocol="--protocol icmp $type"
    return 0
  fi

  protocol=
  return 1
}

# Parse match rules
# @param[string] : the input string in which search for matching rules
# @return[int] : 0 if a match success and the match command is returned in 'match' shell variable
#                1 if no match is performed
function _match() {
  _debug "  reading matching entry : $1"

  if [[ "$1" =~ ^state${C_SEP}${E_REG_STATE}(,${E_REG_STATE})*+$ ]]; then
    _debug "    => match : state : $1"
    match='-m state --state '$(expr match "$1" "state:\($REG_STATE\(,$REG_STATE\)*\)")
    return 0
  elif [[ "$1" =~ ^(c|comment)${C_SEP}[-_a-zA-Z0-9]+$ ]]; then
    _debug "    => match : comment : $1"
    match='-m comment --comment "'$(expr match "$1" '.*:\([-_a-zA-Z0-9]\+\)')'"'
    return 0
  fi

  match=
  return 1
}

# Parse action
# @param[string] : the input string in which search for matching rules
# @return[int] : 0 if a match success and the match command is returned in action' shell variable
#                1 if no match is performed
function _action() {
  _debug "  reading action entry : $1"
  if [[ "$1" =~ ^(j|jump)${C_SEP}(ACCEPT|DROP|RETURN)$ ]]; then
    action="--jump "$(expr match "$1" ".*${C_SEP}\(ACCEPT\|DROP\|RETURN\)")
    return 0
  elif [[ "$1" =~ ^(j|jump)${C_SEP}REJECT(${C_SEP}[-a-zA-Z]+)?$ ]]; then  
    _debug "    => action : REJECT : $1"
    code=$(expr match "$1" ".*${C_SEP}REJECT${C_SEP}\([-a-ZA-Z]\+\)")
    if [[ -n $code ]]; then
      code="--reject-with $code"
    fi
    action="--jump REJECT $code"
    return 0
  elif [[ "$1" =~ ^(j|jump)${C_SEP}MASQUERADE$ && $table = 'nat' && $chain = 'POSTROUTING' ]]; then
      action='--jump MASQUERADE'
      return 0
  fi

  action=
  return 1
}

### ---
### IPTABLES COMMAND
### ---
# This function run specific user defined iptables command to handle iptables option whose are not handled by this script
# @param[string] : the full command string which contains one command by line
# @return[int] : 0 if success
#                105 a incorrect character have been found in given list of command
function _run_command() {
  if [[ "$1" =~ $E_REG_FORBID ]]; then
    _error 'An forbidden character is found'
    return 105
  fi
  _debug "# entering _run_command"
  # set the internal field separator to newline only
  IFS=$'\n'
  for cmd in $1; do
    # if a sharp is found drop this line, it's a comment line
    if [[ ${cmd:0:1} = "#" ]]; then
      _debug "  => comment : $cmd"
      continue
    fi
    IFS=$DEFAULT_IFS
    $IPTABLES $cmd
    if [[ $result -ne 0 ]]; then
      _error 'An error appear during the last command'
      return $result
    fi
    IFS=$'\n'
  done
  # reset the internal field separator for 'for' loop
  IFS=$DEFAULT_IFS
}

###########################
# Restart running process #
###########################
# Check process status and restart it if it is running
# @param[String] : list of process to restart
function restart_process() {
  for process in $1; do
    # Check process status
    _debug "trying to restart $process"
    
    # init.d service
    if [[ -x /etc/init.d/$process ]]; then
      # get the current process status
      /etc/init.d/$process status 2>/dev/null 1>&2
      if [[ $? -eq 0 ]]; then
        # restart the process if it is running
        /etc/init.d/$process restart 2>/dev/null 1>&2
        if [[ $? -ne 0 ]]; then
          # return error if the process can't be restarted
          _error "Process $process hasn't been restarted."
          continue
        fi
      fi
      _echo "$process has been restarted."
    fi
  done
}

############################
# Start the Firewall rules #
############################
# Start function, it setup all firewall rules according to configuration
# @return[int] : 0 if rules have been correctly set
#                X other error codes
function do_start() {
  local r
  _policy 'drop'
  _flush_rules
  _flush_chains
  _reset_counters
  
  # LOAD MAIN RULES
  _load_rules INPUT "$INPUT"
  r=$?; if [[ $r -ne 0 ]]; then return $r; fi
  _load_rules OUTPUT "$OUTPUT"
  r=$?; if [[ $r -ne 0 ]]; then return $r; fi
  
  if _isTrue $IS_ROUTER; then
    _load_rules PREROUTING "$PREROUTING" nat
    r=$?; if [[ $r -ne 0 ]]; then return $r; fi
    
    _load_rules FORWARD "$FORWARD"
    r=$?; if [[ $r -ne 0 ]]; then return $r; fi
    
    _load_rules POSTROUTING "$POSTROUTING" nat
    r=$?; if [[ $r -ne 0 ]]; then return $r; fi
  fi
  
  _run_command "$COMMANDS"
  r=$?; if [[ $r -ne 0 ]]; then return $r; fi
}

###########################
# Stop the Firewall rules #
###########################
# Remove all rules of the firewall, turn it open policy
# @return[int] : 0 if rules have been correctly remove
#               X other error codes
function do_stop() {
  _policy 'accept'
  _flush_rules
  _flush_chains
  _reset_counters
}

##########################
# Restart the Firewall rules
##########################

# Restart all rules of the firewall
# return :	0 if rules have been correctly remove
function do_restart() {
  do_stop
  r=$?
  if [[ $r -ne 0 ]]; then
    _error "Failed to stop the firewall."
    return $r
  fi
  # stop success, now run start
  do_start
  r=$?
  # Trying to restart some depends services
  restart_process "$SERVICES"
  if [[ $r -ne 0 ]]; then
    _error "Failed to start the firewall."
    return $r
  fi
}


#########################
# Rules storage section #
#########################
# Save all firewall rules in a save file
# @param[int] OPTIONNAL : the path of the file in which to save rules
# @return[int] : x	the save command return status
#			203 if save command is not found
function do_save() {
  local file="$1"
  
  if [[ -z "$file" ]]; then
    file=${IPTABLES_BACKUP_FILE}
  fi
  IPTABLES_SAVE=$(which iptables-save 2>/dev/null)
  if [[ -z "${IPTABLES_SAVE}" ]]; then
    _error 'The save command is not found'
    return 203
  fi
  ${IPTABLES_SAVE} > ${file}
}

# Restore all firewall rules from a file
# return :	x	the restore command return status
#			203 if restore command is not found
#			204 restore file is not found
function do_restore() {
  IPTABLES_RESTORE=$(which iptables-restore 2>/dev/null)
  if [[ -z "${IPTABLES_RESTORE}" ]]; then
    _error 'The restore command is not found'
    return 203
  fi
  if [[ -r "${IPTABLES_BACKUP_FILE}" ]]; then
    ${IPTABLES_RESTORE} < ${IPTABLES_BACKUP_FILE}
    return 204
  fi
}


###########################
# Test the Firewall rules #
###########################
# Apply new firewall rules and wait for an user confirmation before saving them
# return :	0 if rules have been correctly set
#           106 if TIMEOUT is not a integer
#			      X other error codes 
function do_test() {
  local r
  local input
  
  if [[ $TIMEOUT_FOR_TEST =~ ^[0-9]+$ ]]; then
    _error 'Incorrect numeric value for TIMEOUT_FOR_TEST option'
    return 106
  fi
  
  echo 'Saving current firewall rules'
  do_save
  r$=?
  if [[ $r -ne 0 ]]; then
    _error 'Unable to save current rules'
    return $r
  fi

  echo 'WARNING : Be careful that the caracters are put to screen after you typed them to ensure a bi-directionnal communication'
  echo "WARNING : Previous configuration will be restore in ${TIMEOUT_FOR_TEST} seconds if no action is performed. Type 'OK' apply new rules [wait for ${TIMEOUT_FOR_TEST}s]"
  echo 'Testing and applying new rules'
  do_restart

  read -t "${TIMEOUT_FOR_TEST}" -n 2 input
  if [[ "$input" =~ ^(o|O)(k|K)$ ]]; then 
    echo 'Saving new rules'
  else
    local debug_file="/tmp/iptables_$(date +%Y-%m-%d_%H-%M)"
    do_save "$debug_file"
    echo 'WARNING : A snapshot of the new firewall rules have been save to $debug_file'
    do_restore
    r$=?
    if [[ $r -ne 0 ]]; then
      _error 'Unable to restore current rules'
      return $r
    fi
    
    _error 'Old rules have been restored'
    return 206
  fi
}


#========== MAIN FUNCTION ==========#
# Main
# @param[] : same of the script
# @return[int] : X the exit code of the script
function main() {
  local r
  
  _isRunAsRoot
  
  ### ARGUMENTS PARSING  
  for i in `seq $(($#+1))`; do
    #catch main arguments
    case $1 in
    -v|--verbose) IS_VERBOSE=1;;
    -d|--debug) IS_DEBUG=1;;
    -*) _error "invalid option -- '$1'"
        exit 201;;
    *)  if [[ $# -ge 1 ]]; then # GOT NEEDED ARGUMENTS
          main_command=$1
          break #stop reading arguments
        else 
          _error 'missing command'
          exit 202
        fi
      ;;
    esac

    if [[ $# -lt 1 ]]; then
      _error 'missing command'
      exit 202
    fi

    shift
  done
  
  ## MAIN CHECK
  # Exit if the iptables command is not available
  if [[ ! -x "$IPTABLES" ]]; then
    _error "The iptables command is not in the path or not installed"
    #exit 203
  fi

  # Exit if the config have not been sourced
  if [[ -z "$IF_CONFIG_SOURCED" ]]; then
    _error "The configuration file have not been source or is not readable"
    exit 204
  fi
  
  # Exit if the defaultaction is invalid
  if [[ ! $DEFAULT_ACTION =~ ^[a-zA-Z]+$ ]]; then
    _error "The default action is not a valid string"
    exit 107
  fi
  

  ### MAIN RUNNING
  case "$main_command" in
  start)
    _echo "Setting firewall rules. Enable firewall secure policy"
    do_start
    r=$?
    case $r in
    0) _echo "=> Success";;
    *) _error "Failed to start the firewall."
      # flush rules after error during start
      do_stop
      exit $r
      ;;
    esac
    ;;
  stop)
    _echo "Removing firewall rules. Turn firewall to open policy"
    do_stop
    r=$?
    case $r in
    0) _echo "=> Success";;
    *) _error "Failed to stop the firewall."; exit $r;;
    esac
    ;;
  restart)
    _echo "Re-setting firewall rules"
    do_restart
    r=$?
    case $r in
    # restart success
    0) _echo "=> Success";;
    *) _error "Failed to restart the firewall."; exit $r;;
    esac
    ;;
  list)
    echo '################ FILTER ################'
    $IPTABLES --table filter --list --line-numbers --numeric --verbose | sed 's/ \/\*/\t\t\/\*/'
    echo '################ NAT ################'
    $IPTABLES --table nat --list --line-numbers --numeric --verbose | sed 's/ \/\*/\t\t\/\*/'
    ;;
  restore)
    _echo "Loading firewall rules from ${IPTABLES_BACKUP_FILE}"
    do_restore
    r=$?
    case "$r" in
    0) _echo "=> Success";;
    *) _echo "=> Failure"; exit $r;;
    esac
    ;;
  save)
    _echo "Saving firewall rules into ${IPTABLES_BACKUP_FILE}"
    do_save
    r=$?
    case "$r" in
    0) _echo "=> Success";;
    *) _echo "=> Failure"; exit $r;;
    esac
    ;;
  test)
    _echo "Testing new firewall rulesets"
    do_test
    r=$?
    case "$r" in
    0) _echo "=> Success";;
    *) _echo "=> Failure"; exit $r;;
    esac
    ;;
  help)
    _usage
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|list|save|restore|help|test}"
    ;;
  esac
}


###### RUNNING ######
# Load global configuration
[[ -r $IPTABLES_CONFIG ]] && source $IPTABLES_CONFIG

main "$@"
