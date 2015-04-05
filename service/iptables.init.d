#!/bin/sh
### BEGIN INIT INFO
# Provides:          iptables
# Required-Start:	   $local_fs
# Required-Stop:	   $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Configure rules for iptables firewall
# Description:       This script load rules for the iptables firewall
### END INIT INFO

# Author Pierre GINDRAUD <pgindraud@gmail.com>

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="Firewall iptables service"
NAME=iptables
DAEMON=/usr/sbin/$NAME-loader
SCRIPTNAME=/etc/init.d/$NAME
DAEMON_ARGS=""

# Exit if the iptables is not installed
[ -x "$DAEMON" ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
#. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions


###########################
# Restart running process #
###########################
# Check process status and restart it if it is running
# @param[string] : list of process to restart
restartProcess() {
  for process in $1; do
    # Check process status
    log_daemon_msg "Trying to restart" "$process"

    # init.d service
    if [ -x /etc/init.d/$process ]; then
      # get the current process status
      /etc/init.d/$process status 2>/dev/null 1>&2
      if [ $? -eq 0 ]; then
        # restart the process if it is running
        /etc/init.d/$process restart 2>/dev/null 1>&2
        if [ $? -eq 0 ]; then
          # success
          log_end_msg 0
          log_success_msg " => service have successfully been restarted"
        else
          # return error if the process can't be restarted
          log_end_msg 1
          log_success_msg " => an error happen during service restarting"
        fi
      else
        log_end_msg 0
        log_success_msg " => service was not running"
      fi
    # no service found
    else
      log_end_msg 0
      log_success_msg " => service not found"
    fi
  done
}


case "$1" in
  start)
    [ "$VERBOSE" != no ] && log_daemon_msg "Setting firewall rules. Enable firewall secure policy" "$NAME"
    # send start command to main script
    $DAEMON start
    r=$?
    case $r in
      0) [ "$VERBOSE" != no ] && log_end_msg 0;;
      *)
        if [ "$VERBOSE" != no ]; then
          log_end_msg 1
          log_failure_msg "$DESC: Failed to start the firewall."
          log_failure_msg "Use $DAEMON help to see the signification of error code : $r"
        fi
      ;;
    esac
  ;;
  stop)
    [ "$VERBOSE" != no ] && log_daemon_msg "Removing firewall rules. Turn firewall to open policy" "$NAME"
    # send stop command to main script
    $DAEMON stop
    r=$?
    case $r in
      0) [ "$VERBOSE" != no ] && log_end_msg 0;;
      *)
        if [ "$VERBOSE" != no ]; then
          log_end_msg 1
          log_failure_msg "$DESC: Failed to stop the firewall."
          log_failure_msg "Use $DAEMON help to see the signification of error code : $r"
        fi
      ;;
    esac
  ;;
  restart|force-reload)
    log_daemon_msg "Re-setting firewall rules" "$NAME"
    # send restart command to main script
    $DAEMON restart
    r=$?
    case $r in
      # restart success
      0)
        log_end_msg 0
        # trying to restart some depends process
        restartProcess "$SERVICES"  
      ;;
      # start failed
      *)
        log_end_msg 1
        log_failure_msg "$DESC: Failed to restart the firewall."
        log_failure_msg "Use $DAEMON help to see the signification of error code : $r"
      ;;
    esac
  ;;
  test)
    log_action_msg "Testing new firewall rulesets" "$NAME"
    $DAEMON test
    r=$?
    case "$r" in
      0)
        log_success_msg "New rules successfully applied"
        # trying to restart some depends process
        restartProcess "$SERVICES"
      ;;
      *) log_failure_msg "Use '$DAEMON help' to see the signification of error code : $r"
      ;;
    esac
  ;;
  *)
    echo "Usage: $SCRIPTNAME {start|stop|restart|force-reload|test}" >&2
    exit 3
  ;;
esac

: