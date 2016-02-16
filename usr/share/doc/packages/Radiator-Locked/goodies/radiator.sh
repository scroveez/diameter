#!/bin/sh

# PROVIDE: radiator
# REQUIRE: DAEMON
# BEFORE: LOGIN
# KEYWORD: FreeBSD shutdown

# Install this script as /usr/local/etc/rc.d/radiator
# Add the following line to /etc/rc.conf to enable "radiator":
#
#radiator_enable="YES"
#
# And if necessary:
#
#radiator_config="/path/to/radiator.conf"
#(default config location is /etc/radiator/radius.cfg)
#
#radiator_flags=""
#
# Start /usr/local/etc/rc.d/radiator to see a list of options.

. /etc/rc.subr

name="radiator"
rcvar=`set_rcvar`
pidfile="/var/run/radiator.pid"
command="/usr/local/bin/radiusd"
procname="/usr/local/bin/perl"
extra_commands="reload"

stop_postcmd=stop_postcmd

stop_postcmd()
{
  rm -f $pidfile
}

load_rc_config $name

: ${radiator_enable="NO"}
: ${radiator_flags=""}
: ${radiator_config="/etc/radiator/radius.cfg"}

required_files="$radiator_config"

command_args="-pid_file=${pidfile} -config_file=$radiator_config"

run_rc_command "$1"

