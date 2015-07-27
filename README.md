# Iptables Loader

This project is licensed under the terms of the MIT license

This is a shell script which provide a way to load iptables rules based on a configuration file.

It consists in a main script iptables.sh, which read a configuration file and load all iptables rules according to this.

The main script is independant, if you want to load it as a system service (for example at boot time) you have to write a service script according to your distribution boot system (init, systemd ...)

Take care, the default given configuration correspond to a server usage, and it's that why, some basic rules must not be configured to allow basic traffic.


## Usage

Run the script as root user manually from it location like

```bash
  ./iptables-loader.sh COMMAND  
```

Use the `help` command to show the full list of COMMAND

!!!! Use the test command to start the firewall after rules editing.
It provide a facility to rollback if error cause lost of connection


## Configuration

See the CONFIG.md file for configuration details

[Configuration](CONFIG.md)

## Installation

Currently this script is only available for System-V init

### On debian installation

  1. Put the script into an appropriate folder and copy the service files from github service/ folder into your system /etc/init.d/ folder
  2. You can build the Debian deb package with the given Makefile. Use `make package-debian` then `make build-debian` 
    The service can be managed by /etc/init.d/iptables script or by the distribution available command such as ```service```

##### Requires:
  * A Debian based distribution


### In all installation

Put the script in a appropriate folder and write a system service script according to your booting manager if you want to run the firewall automatically at startup

##### Requires:
  * A Linux kernel > 2.4
  * The `iptables` command

  * xtables-addons to use some extra features