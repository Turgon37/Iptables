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
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions


###########################
# Restart running process #
###########################
# Check process status and restart it if it is running
# @param[string] : list of process to restart
function restartProcess() {
  for process in $1; do
    # Check process status
    log_daemon_msg "trying to restart $process"
    
    # init.d service
    if [ -x /etc/init.d/$process ]; then
      # get the current process status
      /etc/init.d/$process status 2>/dev/null 1>&2
      if [ $? -eq 0 ]; then
        # restart the process if it is running
        /etc/init.d/$process restart 2>/dev/null 1>&2
        if [ $? -ne 0 ]; then
          # return error if the process can't be restarted
          echo "Process $process hasn't been restarted." 1>&2
        else
          echo "$process has been restarted."
        fi
      fi
    fi
  done
}



case "$1" in
  start)
    [ "$VERBOSE" != no ] && log_daemon_msg "Setting firewall rules. Enable firewall secure policy" "$NAME"
    $DAEMON start
    case $? in
      0) [ "$VERBOSE" != no ] && log_end_msg 0;;
      *)
        if [ "$VERBOSE" != no ]; then
          log_end_msg 1
          log_failure_msg "$DESC: Failed to start the firewall."
        fi
      ;;
    esac
  ;;
  stop)
    [ "$VERBOSE" != no ] && log_daemon_msg "Removing firewall rules. Turn firewall to open policy" "$NAME"
    $DAEMON stop
    case $? in
      0) [ "$VERBOSE" != no ] && log_end_msg 0;;
      *)
        if [ "$VERBOSE" != no ]; then
          log_end_msg 1
          log_failure_msg "$DESC: Failed to start the firewall."
        fi
      ;;
    esac
  ;;
  restart|force-reload)
    log_daemon_msg "Re-setting firewall rules" "$NAME"
    $DAEMON restart
    case $? in
      # restart success
      0)
        log_end_msg 0
        # trying to restart some depends process
        restartProcess "$SERVICES";;
      # start failed
      *) log_end_msg 1
        log_failure_msg "$DESC: Failed to restart the firewall."
      ;;
    esac
  ;;
  restore)
    log_daemon_msg "Loading firewall rules from backup file" "$NAME"
    $DAEMON restore
    case "$?" in
    0) log_end_msg 0 ;;
    *) log_end_msg 1 ;;
    esac
  ;;
  save)
    log_daemon_msg "Saving firewall rules to backup file" "$NAME"
    $DAEMON save
    case "$?" in
    0) log_end_msg 0 ;;
    *) log_end_msg 1 ;;
    esac
  ;;
  test)
    log_action_msg "Testing new firewall rulesets" "$NAME"
    $DAEMON test
  ;;
  help)
    $DAEMON help
  ;; 
  *)
    echo "Usage: $SCRIPTNAME {start|stop|restart|force-reload|save|restore|help|test}" >&2
    exit 3
  ;;
esac

: