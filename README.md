# Iptables

This project is licensed under the terms of the MIT license

This is a shell script which provide a way to load iptables rules based on a configuration file.

It consist in a main script iptables.sh which is launch by init(1) program and a configuration file localized by default to /etc/default/iptables

The main script is written to run as a service script

Currently the script is provided only for distributions based on Debian

## Usage

Run the script as another service script, include it in system boot sequence using `update-rc.d` and launch it with `service` command

```bash
  ./iptables COMMAND
```

## Installation

Put the script it in the /etc/init.d/ folder

##### Requires:
  * A Debian based distribution
