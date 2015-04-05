# Iptables

This project is licensed under the terms of the MIT license

This is a shell script which provide a way to load iptables rules based on a configuration file.

It consists in a main script iptables.sh, which read a configuration file and load all iptables rules according to this.

The main script is independant, if you want to load it as a system service (for example at boot time) you have to write a service script according to your distribution boot system (init, systemd ...)

Take care, the default given configuration correspond to a server usage, and it's that why, some basic rules must not be configured to allow basic traffic.


## Usage

Run the script as root user manually from it location like

```bash
  ./iptables.sh COMMAND  
```

Use the `help` command to show the full list of COMMAND

## Configuration

See the CONFIG.md file for configuration details

[Configuration](CONFIG.md)

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