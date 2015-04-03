#!/bin/bash
#title         :Debian package building
#description   :Configure rules for iptables firewall
#author        :P.GINDRAUD
#author_contact:pgindraud@gmail.com
#created_on    :2015-03-29
#usage         :./build_deb.sh
#==============================================================================
# CHANGE THIS TO THE NAME OF YOUR PROGRAM, THIS NAME WILL BE THE PACKAGE NAME
NAME=iptables-loader



#========== INTERNAL OPTIONS ==========#
DPKG_DEB=$(which dpkg-deb 2>/dev/null)
SUDO=$(which sudo 2>/dev/null)

#========== INTERNAL VARIABLES ==========#
PACKAGE_ROOT=deb/$NAME
PROJECT=..
VERSION=$(grep '--ignore-case' 'version' DEBIAN/control | grep -Eo '[0-9]+(\.[0-9]+)+')


#========== INTERNAL FUNCTIONS ==========#

# Print a msg to stderr if verbose option is set
# @param[string] : the msg to write in stderr
function _error() {
  echo -e "Error : $@" 1>&2
}

# Check if the script is run by root or not. If not, prompt error and exit
function _isRunAsRoot() {
  if [[ -z $SUDO && "$(id -u)" != "0" ]]; then
    _error "This script must be run as root." 1>&2
    exit 200
  fi
}

function buildTree() {
  echo ' * Building package tree...'
  if [[ ! -d deb ]]; then
    echo '    => Make the deb directory'
    mkdir deb
    echo '    => Create the full classic debian package tree'
    mkdir -p deb/$NAME/DEBIAN/
    mkdir -p deb/$NAME/etc/default/
    mkdir -p deb/$NAME/etc/init.d/
    mkdir -p deb/$NAME/usr/sbin
    #mkdir -p deb/$NAME/usr/bin
    chmod -R 755 $PACKAGE_ROOT/*
  else
    echo ' # Deb directory already exists'
    exit 0
  fi
}

function copyFile() {
  echo ' * Copying main files...'
  if [[ -d deb ]]; then
    echo '    => Copy package description files'
    cp -R DEBIAN/* deb/$NAME/DEBIAN/
    # mod for script files
    chmod -R 755 $PACKAGE_ROOT/DEBIAN/p*
    # mod for text files
    chmod -R 644 $PACKAGE_ROOT/DEBIAN/c*
  else
    echo ' # Deb directory does not exists'
  fi
}

function chmodToRoot() {
  $SUDO chown -R root:root $PACKAGE_ROOT
  $SUDO chown -R root:root $PACKAGE_ROOT/*
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
    -*)
      _error "invalid option -- '$1'"
      exit 201
      ;;
    esac

    shift
  done

  # MAIN CHECK
  if [[ -z $VERSION ]]; then
    _error 'Cannot retrieve package version automatically please set it manually'
    exit 100
  fi

  ### MAIN RUNNING
  umask 022
  
  buildTree
  copyFile
  
  
  echo ' * Applying user building rules...'
  # SET HERE THE COMMAND TO RUN BEFORE MAKE THE PACKET
  # SUCH AS cp BINARY FILE AND MAKE SOME CHMOD

  # copy configuration
  cp $PROJECT/iptables.conf $PACKAGE_ROOT/etc/default/$NAME
  chmod 640 $PACKAGE_ROOT/etc/default/$NAME
  # copy service
  cp $PROJECT/service/iptables.init.d $PACKAGE_ROOT/etc/init.d/$NAME
  chmod 644 $PACKAGE_ROOT/etc/init.d/$NAME

  # copy executable files
  cp $PROJECT/iptables.sh $PACKAGE_ROOT/usr/sbin/$NAME
  chmod 755 $PACKAGE_ROOT/usr/sbin/$NAME

  
  echo ' * Chmoding all tree to root:root...'
  chmodToRoot


  # BUILDING package
  echo ' * Building package...'
  if [[ -n $DPKG_DEB ]]; then
    cd deb
    $DPKG_DEB --build $NAME
    mv $NAME.deb $NAME_$VERSION.deb
    echo "  ==> The final package is available in $NAME_$VERSION.deb"
  else
    $SUDO tar cfz $NAME.tar.gz $PACKAGE_ROOT
    echo "  ==> The package tree is available in $NAME.tar.gz"
  fi
}


###### RUNNING ######
main "$@"