#!/bin/bash
#title         :iptables-loader
#description   :Configure rules for iptables firewall
#author        :P.GINDRAUD, T.PAJON
#author_contact:pgindraud@gmail.com,th.pajon45@gmail.com
#created_on    :2014-05-30
#usage         :./iptables <CMD>
#usage_info    :use command 'help'
#options       :debug
#notes         :
# This script is currently under development, please take a real care to report
# all errors, and don't worry about using debug option to control the good
#  running of the script
readonly VERSION='3.3.3'
#==============================================================================
INPUT=
OUTPUT=
FORWARD=
PREROUTING=
POSTROUTING=
IS_ROUTER=0
DEFAULT_ACTION=ACCEPT
DEFAULT_TABLE=filter
TIMEOUT_FOR_TEST=5


#========== INTERNAL OPTIONS ==========#
readonly IPTABLES=$(which iptables 2>/dev/null)
readonly IP6TABLES=$(which ip6tables 2>/dev/null)

readonly IPTABLES_CONFIG=/etc/default/iptables
readonly IPTABLES_BACKUP_FILE=/etc/iptables.backup

# The key => config separator
readonly C_SEP=':'


#========== INTERNAL VARIABLES ==========#
IS_SIMULATION=0
IS_DEBUG=0
IS_VERBOSE=0

readonly DEFAULT_IFS=$IFS
## WORKING REGEX
# Don't touch unless you know what you are doing
# all regex whose begin with E_ prefix are wrote in extended regex language
# REGEX that describe a string thaht must not be present in all configuration string, this regexp must be an only | characters alternatives
readonly E_REG_FORBID='(\;)'

# REGEX that describe a IFACE name
readonly REG_IFACE='\([a-zA-Z*][a-zA-Z0-9*.:-]*+\?\)'
readonly REG_E_IFACE='([a-zA-Z*][a-zA-Z0-9*.:-]*\+?)'

# REGEX that describe a port number (between 1 and 65535)
readonly REG_PORT='\([0-9]\{1,4\}\|[1-5][0-9]\{4\}\|6[0-4][0-9]\{3\}\|65[0-4][0-9]\{2\}\|655[0-2][0-9]\|6553[0-5]\)'
readonly REG_E_PORT='([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])'

# REGEX that describe a port range like PORT-PORT (use this for port matching)
readonly REG_RANGE="\(${REG_PORT}\(:${REG_PORT}\)\?\)"
readonly REG_E_RANGE="(${REG_E_PORT}(:${REG_E_PORT})?)"

# REGEX that qualify a network which has a gateway
readonly REG_E_GW="(${C_SEP}gw)"

#========== INTERNAL FUNCTIONS ==========#

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
  -s, --simulate  No action
  -v, --verbose   Show more running messages
  -d, --debug     Show debug messages

Return code :
  0     Success
  1-98  Reserved for iptables error code
  99    Unknown error
  100   Error input rules in a output chains
  101   Error output rules in a input chains
  102   Bad or missing syntax in rule
  105   Incorrect character in configuration file
  106   Incorrect numeric value for a variable
  107   Incorrect string value for a variable
  200   Need to be root
  201   Bad system arguments
  202   Missing COMMAND in shell args
  203   Missing a system needed program
  204   Unable to load configuration file
  205   Missing restore file
  206   Error during restore command
  207   'test' command fail, new rules cause a break of connection
"
}

# Print a msg to stdout if verbose option is set
# @param[string] : the msg to write in stdout
function _echo() {
  if [[ $IS_VERBOSE -eq 1 ]]; then
    echo -e "$*"
  fi
}

# Print a msg to stderr if verbose option is set
# @param[string] : the msg to write in stderr
function _error() {
  if [[ $IS_VERBOSE -eq 1 ]]; then
    echo -e "Error : $*" 1>&2
  fi
}

# Print a msg to stderr if verbose option is set
# @param [string] : the msg to write in stderr
# @param [int] : the line number
# @param [string] : the name of key in config
function _error_config() {
  _error "$1 at line $2 in $3"
}

# Print a msg to stdout if debug verbose is set
# @param[string] : the msg to write in stdout
function _debug() {
  if [[ $IS_DEBUG -eq 1 ]]; then
    echo -e "debug: $*"
  fi
}

# Check if the script is run by root or not. If not, prompt error and exit
function _isRunAsRoot() {
  if [[ "$(id -u)" != "0" ]]; then
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
# @return[string] : If the regex match, return the IPV4 address name
#                   which is contains in $1
function parseAddress() {
  expr match "$1" "${2}\([a-z0-9A-Z:,./]\+\)${3}"
}

# Retrieve the iface name string from a input string
# @param[string] : the input string
# @param[string] OPTIONNAL : the REGEX prefix
# @param[string] OPTIONNAL : the REGEX suffix
# @return[string] : If the regex match, return the IFACE name
#                   which is contains in $1
function parseIface() {
  expr match "$1" "${2}${REG_IFACE}${3}"
}

### ---
### TABLES MGMT
### ---
# Remove all rules in all chains
function _flush_rules() {
  _debug 'entering flush rules'
  _run_command '--flush' '--table filter'
  _run_command '--flush' '--table nat'
  _run_command '--flush' '--table mangle'
}
# Remove all user defined chains (these what are not built in)
function _flush_chains() {
  _debug 'entering flush chains'
  _run_command '--delete-chain' '--table filter'
  _run_command '--delete-chain' '--table nat'
  _run_command '--delete-chain' '--table mangle'
}
# Reset all packets counter
function _reset_counters() {
  _debug 'entering reset counter'
  _run_command '--zero' '--table filter'
  _run_command '--zero' '--table nat'
  _run_command '--zero' '--table mangle'
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
    pol='
--policy INPUT ACCEPT
--policy OUTPUT ACCEPT'

    if _isTrue $IS_ROUTER; then
      pol="$pol
--policy FORWARD ACCEPT"
    else
      pol="$pol
--policy FORWARD DROP"
    fi
    _run_command "$pol" '--table filter'

    # NAT
    pol='
--policy PREROUTING ACCEPT
--policy OUTPUT ACCEPT
--policy INPUT ACCEPT
--policy POSTROUTING ACCEPT'
    _run_command "$pol" '--table nat'
  elif [[ "$1" = 'drop' ]]; then
    _debug 'setting policy to drop'
    # FILTER
    pol='
--policy INPUT DROP
--policy OUTPUT DROP
--policy FORWARD DROP'
    _run_command "$pol" '--table filter'
  else
    _error 'Undefined global policy'
  fi
}

### ---
### GLOBAL RULES LOADING
### ---
# Load network rules
# @param [string] : the configuration string from configuration file
# @param [string] OPTIONNAL : the name of the chain in which to load the rules
#                           if set to 'NONE' =>disable auto complete
# @param [string] OPTIONNAL : the table name in which include new rules
# @return [int] : 0 if all rule are correctly set
#                X  the iptables return code
#                100 if an input rule is declare with a output chain
#                101 if an output rule is declare with a input chain
#                102 if missing or wrong syntax in rule
#                105 a incorrect character have been found in given list of command
function _load_rules() {
  local chain=$2
  local table=$3
  local line=0

  if [[ "$2" =~ $E_REG_FORBID ]]; then
    _error 'An forbidden character is found'
    return 105
  fi
  _debug "# entering _load_rules : $2"
  # set the internal field separator to newline only
  IFS=$'\n'
  # Loop for each rule (separated by space)
  for entry in $1; do
    line=$(($line+1))
    _debug "reading config entry : $entry"
    # if a sharp is found drop this line, it's a comment line
    if [[ ${entry:0:1} = "#" ]]; then
      _debug "  => comment : $entry"
      continue
    fi
    local table_add=
    local method_add=
    local src_address=
    local dst_address=
    local in_iface=
    local out_iface=
    local protocol_opt=
    local match_opt=
    local action_opt=
    local other_opt=

    IFS=$DEFAULT_IFS
    # Loop for each command (separated by F_SEP, pipe as default)
    for c in $entry; do
      local r=0

      # SOURCE ADDRESS matching
      if [[ "$c" =~ ^(s|src)${C_SEP}.*$ ]]; then
        _debug "  => src addr : $c"
        src_address=$(parseAddress "$c" '.*'${C_SEP})
        if [[ -n $src_address && $src_address != '*' ]]; then
          src_address="--source $src_address"
        else
          _error_config "Missing source address" $line $chain
          return 102
        fi
      # DESTINATION ADDRESS matching
      elif [[ "$c" =~ ^(d|dst)${C_SEP}.*$ ]]; then
        _debug "  => dst addr : $c"
        dst_address=$(parseAddress "$c" '.*'${C_SEP})
        if [[ -n $dst_address && $dst_address != '*' ]]; then
          dst_address="--destination $dst_address"
        else
          _error_config "Missing destination address" $line $chain
          return 102
        fi
      # INPUT INTERFACE matching
      elif [[ "$c" =~ ^(i|in)${C_SEP}.*$ ]]; then
        _debug "  => in iface : $c"
        # interface
        in_iface=$(parseIface "$c" '.*'${C_SEP})
        if [[ -n $in_iface ]]; then
          # error during forward rule with an unique interface
          if [[ "$2" =~ OUTPUT|POSTROUTING ]]; then
            _error_config "Input interface specified in OUTPUT rule" $line $chain
            return 101
          fi
          in_iface="--in-interface $in_iface"
        else
          _error_config "Bad interface name" $line $chain
          return 102
        fi
      # OUTPUT INTERFACE matching
      elif [[ "$c" =~ ^(o|out)${C_SEP}.*$ ]]; then
        _debug "  => out iface : $c"

        # output interface
        out_iface=$(parseIface "$c"  '.*'${C_SEP})
        if [[ -n $out_iface ]]; then
          # error during forward rule with an unique interface
          if [[ "$2" =~ INPUT|PREROUTING ]]; then
            _error_config "Output interface specified in INPUT rule" $line $chain
            return 100
          fi
          out_iface="--out-interface $out_iface"
        else
          _error_config "Bad interface name" $line $chain
          return 102
        fi
      # PROTOCOL matching
      elif _protocol "$c"; then
        if [[ $r -ne 0 ]]; then
          return 102
        fi
        protocol_opt="$protocol_opt $protocol"
      # MATCH matching
      elif _match "$c"; then
        match_opt="$match_opt $match"
      else
        _debug "  => other : $c"
        other_opt="$other_opt $c"
      fi
    done

    if [[ $chain != 'NONE' ]]; then
      if [[ ! "$entry" =~ ^.*(-t|--table).*$ ]]; then
        if [[ -z $table ]]; then
          table="--table $DEFAULT_TABLE"
        else
          table="--table $table"
        fi
      fi

      # NO ADD METHOD
      if [[ ! "$entry" =~ ^.*(-A|--append|-I|--insert).*$ && -n $chain ]]; then
        method_add="--append $chain"
      fi

      # NO ACTION in the entire line => default action
      if [[ -n $DEFAULT_ACTION && -z $action_opt && ! "$entry" =~ ^.*(-j|--jump).*$ ]]; then
        action_opt="--jump $DEFAULT_ACTION"
      fi
    fi
    _run_command "$table_add $method_add $in_iface $out_iface $src_address $dst_address $protocol_opt $match_opt $other_opt $action_opt"
    r=$?
    if [[ $r -ne 0 ]]; then
      _error_config 'An error appear during the last command' $line $chain
      return $r
    fi
    IFS=$'\n'
  done
  # reset the internal field separator for 'for' loop
  IFS=$DEFAULT_IFS
  return 0
}

# Parse protocol rules
# @param [string] : the input string in which search for matching rules
# @return [int] : 0 if a match success and the match command is returned in
#                         'protocol' shell variable
#                1 if no match is performed
function _protocol() {
  _debug "  reading protocol entry : $1"
  r=0

  # TCP matching
  if [[ "$1" =~ ^tcp$ ]]; then
    _debug "    => proto tcp : $1"
    protocol="--protocol tcp"
    return 0
  # UDP matchingTIMEOUT_FOR_TEST
  elif [[ "$1" =~ ^udp$ ]]; then
    _debug "    => proto udp : $1"
    protocol="--protocol udp"
    return 0
  elif [[ "$1" =~ ^sp${C_SEP}.*$ ]]; then
    local src_port
    src_port=$(expr match "$1" "sp${C_SEP}${REG_RANGE}")
    if [[ -z $src_port  ]]; then
      r=102
      _error 'Empty source port'
    fi
    protocol="--source-port $src_port"
    return 0
  elif [[ "$1" =~ ^dp${C_SEP}.*$ ]]; then
    local src_port
    dst_port=$(expr match "$1" "dp${C_SEP}${REG_RANGE}")
    if [[ -z $dst_port  ]]; then
      r=102
      _error 'Empty destination port'
    fi
    protocol="--destination-port $dst_port"
    return 0
  # ICMP matching
  elif [[ "$1" =~ ^icmp(${C_SEP}[-a-zA-Z0-9/]+)?$ ]]; then
    _debug "    => proto icmp : $1"
    local type=

    type=$(expr match "$1" ".*${C_SEP}\([-a-zA-Z0-9/]\+\)")
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
  if [[ "$1" =~ ^(c|comment)${C_SEP}[-_a-zA-Z0-9]+$ ]]; then
    _debug "    => match : comment : $1"
    match='-m comment --comment '$(expr match "$1" ".*${C_SEP}\([-_a-zA-Z0-9]\+\)")
    return 0
  fi
  match=
  return 1
}

### ---
### IPTABLES COMMAND
### ---
# This function run specific user defined iptables command to handle iptables option whose are not handled by this script
# @param[string] : the full command string which contains one command by line
# @param[string] : a string prefix to put in front of each rules
# @return[int] : 0 if success
#                105 a incorrect character have been found in given list of command
function _run_command() {
  local prefix="$2"
  if [[ "$1" =~ $E_REG_FORBID || "$prefix" =~ $E_REG_FORBID ]]; then
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
    if [[ "$cmd" =~ ^( )*$|^$ ]]; then
      continue
    fi
    IFS=$DEFAULT_IFS
    cmd="$prefix $cmd"
    _debug "  => command : $cmd"
    if [[ $IS_SIMULATION -eq 1 ]]; then
      echo -e "SIMULATE: $cmd"
    else
      $IPTABLES $cmd
    fi

    r=$?
    if [[ $r -ne 0 ]]; then
      _error 'An error appear during the last command'
      return $r
    fi
    IFS=$'\n'
  done
  # reset the internal field separator for 'for' loop
  IFS=$DEFAULT_IFS
}

############################
# Start the Firewall rules #
############################
# Start function, it setup all firewall rules according to configuration
# @return[int] : 0 if rules have been correctly set
#                X other error codes
function do_start() {
  local r
  _flush_rules
  _flush_chains
  _reset_counters

  # MANUALS RULES
  _load_rules "$COMMANDS" 'NONE'
  r=$?; if [[ $r -ne 0 ]]; then return $r; fi

  # LOAD MAIN RULES
  _load_rules "$INPUT" 'INPUT'
  r=$?; if [[ $r -ne 0 ]]; then return $r; fi
  _load_rules "$OUTPUT" 'OUTPUT'
  r=$?; if [[ $r -ne 0 ]]; then return $r; fi

  # ROUTING RULES
  if _isTrue $IS_ROUTER; then
    _load_rules "$PREROUTING" 'PREROUTING' 'nat'
    r=$?; if [[ $r -ne 0 ]]; then return $r; fi

    _load_rules "$FORWARD" 'FORWARD'
    r=$?; if [[ $r -ne 0 ]]; then return $r; fi

    _load_rules "$POSTROUTING" 'POSTROUTING' 'nat'
    r=$?; if [[ $r -ne 0 ]]; then return $r; fi
  fi

  _policy 'drop'
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
#     205 if restore file is not found
#     206 if restore command fail
function do_restore() {
  IPTABLES_RESTORE=$(which iptables-restore 2>/dev/null)
  if [[ -z "${IPTABLES_RESTORE}" ]]; then
    _error 'The restore command is not found'
    return 203
  fi
  if [[ -r "${IPTABLES_BACKUP_FILE}" ]]; then
    ${IPTABLES_RESTORE} < ${IPTABLES_BACKUP_FILE}
    if [[ $? -ne 0 ]]; then
      return 206
    fi
  else
    return 205
  fi
}

###########################
# Test the Firewall rules #
###########################
# Apply new firewall rules and wait for an user confirmation before saving them
# return :	0 if rules have been correctly set
#           106 if TIMEOUT is not a integer
#           207 if general test fail
function do_test() {
  local r
  local input

  if [[ ! $TIMEOUT_FOR_TEST =~ ^[0-9]+$ ]]; then
    _error "Incorrect numeric value : $TIMEOUT_FOR_TEST given for test timeout"
    return 106
  fi

  echo ' * Saving current firewall rules'
  do_save
  r=$?
  if [[ $r -ne 0 ]]; then
    _error 'Unable to save current rules'
    return $r
  fi

  echo 'You have to confirm that the new rules are being set safety'
  echo 'To do that it will be ask you to type a confirm keyword otherwise old rules will be restored'
  echo
  echo 'WARNING : Be careful that the caracters are written to the screen after you have typed them to ensure a bi-directionnal communication'
  echo "WARNING : Previous configuration will be restore in ${TIMEOUT_FOR_TEST} seconds if no action is performed."
  echo
  echo 'After typing the word "start" (with correct case) the new rules are going to be tested'

  while [[ $input != start ]]; do
    read -n 5 input
    if [[ $input != start ]]; then
      echo -e '\nPlease carrefully read the message above and try again...'
    fi
  done

  echo -e '\n * Testing new rules...'
  echo "Type 'ok' (ignore case) to apply new rules [wait for ${TIMEOUT_FOR_TEST}s]"
  do_restart

  read -t "${TIMEOUT_FOR_TEST}" -n 2 input
  if [[ "$input" =~ ^(o|O)(k|K)$ ]]; then
    echo -e '\n * Applying new rules'
  else
    local debug_file

    debug_file="/tmp/iptables_$(date +%Y-%m-%d_%H-%M)"
    do_save "$debug_file"
    echo ' * Rollback old rules'
    echo "WARNING : A snapshot of the new firewall rules have been save to $debug_file"
    do_restore
    r=$?
    if [[ $r -ne 0 ]]; then
      _error 'Unable to restore current rules'
      return $r
    fi

    _error 'Old rules have been restored'
    return 207
  fi
}


#========== MAIN FUNCTION ==========#
# Main
# @param[] : same of the script
# @return[int] : X the exit code of the script
function main() {
  local ret

  _isRunAsRoot

  ### ARGUMENTS PARSING
  for i in $(seq $(($#+1))); do
    #catch main arguments
    case $1 in
    -s|--simulate) IS_SIMULATION=1;;
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
    exit 203
  fi

  # Exit if the config have not been sourced
  if [[ -z "$IF_CONFIG_SOURCED" ]]; then
    _error "The configuration file have not been source or is not readable"
    exit 204
  fi

  # Exit if the defaultaction is invalid
  if [[ -n $DEFAULT_ACTION && ! $DEFAULT_ACTION =~ ^[a-zA-Z]+$ ]]; then
    _error "The default action is not a valid string"
    exit 107
  fi


  ### MAIN RUNNING
  case "$main_command" in
  start)
    _echo "Setting firewall rules. Enable firewall secure policy"
    do_start
    ret=$?
    case $ret in
    0) _echo "=> Success";;
    *) _error "Failed to start the firewall."
      # flush rules after error during start
      do_stop
      exit $ret
      ;;
    esac
    ;;
  stop)
    _echo "Removing firewall rules. Turn firewall to open policy"
    do_stop
    ret=$?
    case $ret in
    0) _echo "=> Success";;
    *) _error "Failed to stop the firewall."; exit $ret;;
    esac
    ;;
  restart)
    _echo "Re-setting firewall rules"
    do_restart
    ret=$?
    case $ret in
    # restart success
    0) _echo "=> Success";;
    *) _error "Failed to restart the firewall."; exit $ret;;
    esac
    ;;
  list)
    echo '################ FILTER ################'
    $IPTABLES --table filter --list --line-numbers --verbose | sed 's/ \/\*/\t\t\/\*/'
    echo '################ NAT ################'
    $IPTABLES --table nat --list --line-numbers --verbose | sed 's/ \/\*/\t\t\/\*/'
    ;;
  restore)
    _echo "Loading firewall rules from ${IPTABLES_BACKUP_FILE}"
    do_restore
    ret=$?
    case $ret in
    0) _echo "=> Success";;
    *) _echo "=> Failure"; exit $ret;;
    esac
    ;;
  save)
    _echo "Saving firewall rules into ${IPTABLES_BACKUP_FILE}"
    do_save
    ret=$?
    case $ret in
    0) _echo "=> Success";;
    *) _echo "=> Failure"; exit $ret;;
    esac
    ;;
  test)
    _echo "Testing new firewall ruleset"
    do_test
    ret=$?
    case $ret in
    0) _echo "=> Success";;
    *) _echo "=> Failure"; exit $ret;;
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
[[ -r $IPTABLES_CONFIG ]] && source "$IPTABLES_CONFIG"

main "$@"
