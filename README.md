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

## Configuration

The default configuration file's location is in /etc/default/iptable
The configuration file consist in a simple shell script which contains only variable declaration because it is simply sourced at the iptables.sh startup.


## Installation

### In debian installation

Put the script into an appropriate folder and copy the service files from github init.d/ folder into your system /etc/init.d/ folder
or simply install the provided deb package


### In all installation

Put the script in a appropriate folder


##### Requires:
  * A Debian based distribution
