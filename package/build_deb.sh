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
PACKAGE_DOC=$PACKAGE_ROOT/usr/share/doc/$NAME/
PROJECT=..
VERSION=$(grep '--ignore-case' 'version' DEBIAN/control | grep -Eo '[0-9]+(\.[0-9]+)+')
ARCH=$(grep '--ignore-case' 'architecture' DEBIAN/control | cut -d : -f 2- | grep -Eo '[a-ZA-Z]+')

ARCHIVE=${NAME}_${VERSION}_${ARCH}

#========== INTERNAL FUNCTIONS ==========#

# Print a msg to stderr if verbose option is set
# @param[string] : the msg to write in stderr
function _error() {
  echo -e "Error : $@" 1>&2
}

# Check if the script is run by root or not. If not, prompt error and exit
function _isRunAsRoot() {
  if [[ $(id -u) == "0" ]]; then
    SUDO=
    return
  fi
  if [[ -z $SUDO ]]; then
    _error "This script must be run as root." 1>&2
    exit 200
  fi
}

function buildPackageTree() {
  echo ' * Building package tree...'
  if [[ ! -d deb ]]; then
    echo '    => Make the deb directory'
    mkdir -p $PACKAGE_ROOT
    echo '    => Create the full classic debian package tree'
    mkdir -p $PACKAGE_ROOT/DEBIAN/
    
    mkdir -p $PACKAGE_ROOT/etc/default/
    mkdir -p $PACKAGE_ROOT/etc/init.d/
    
    mkdir -p $PACKAGE_ROOT/usr/sbin
    #mkdir -p $PACKAGE_ROOT/usr/bin
    mkdir -p $PACKAGE_DOC
    mkdir -p $PACKAGE_DOC/examples
    
    #mkdir -p $PACKAGE_ROOT/var/run
    
    chmod -R 755 $PACKAGE_ROOT/*
  else
    echo ' # Deb directory already exists'
    exit 0
  fi
}

function installDebianFiles() {
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
    exit 1
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
  
  echo ' * Applying package building rules...'
  buildPackageTree
  cp $PROJECT/LICENCE $PACKAGE_ROOT/DEBIAN/copyright
  installDebianFiles
  
  
  echo ' * Applying user building rules...'
  # SET HERE THE COMMAND TO RUN BEFORE MAKE THE PACKET
  # SUCH AS cp BINARY FILE AND MAKE SOME CHMOD

  # copy configuration
  cp $PROJECT/iptables.conf $PACKAGE_ROOT/etc/default/iptables
  chmod 640 $PACKAGE_ROOT/etc/default/iptables
  
  # copy docs
  cp $PROJECT/iptables.conf $PACKAGE_DOC/examples/iptables.conf
  cp DEBIAN/changelog $PACKAGE_DOC/
  cp $PROJECT/README.md $PACKAGE_DOC/
  cp $PROJECT/LICENCE $PACKAGE_DOC/copyright
  # copy service
  cp $PROJECT/service/iptables.init.d $PACKAGE_ROOT/etc/init.d/iptables
  chmod 755 $PACKAGE_ROOT/etc/init.d/iptables

  # copy executable files
  cp $PROJECT/iptables.sh $PACKAGE_ROOT/usr/sbin/$NAME
  chmod 755 $PACKAGE_ROOT/usr/sbin/$NAME

  
  echo ' * Chmoding all tree to root:root...'
  chmodToRoot


  # BUILDING package
  echo ' * Building package...'
  if [[ -n $DPKG_DEB ]]; then
    cd deb
    $SUDO $DPKG_DEB --build ${NAME}
    $SUDO mv $NAME.deb ${ARCHIVE}.deb
    $SUDO chmod 644 ${ARCHIVE}.deb
    echo "  ==> The final package is available in ${ARCHIVE}.deb"
  else
    $SUDO tar cfz ${ARCHIVE}.tar.gz $PACKAGE_ROOT
    $SUDO chmod 644 ${ARCHIVE}.tar.gz
    echo "  ==> The package tree is available in ${ARCHIVE}.tar.gz"
  fi
}


###### RUNNING ######
main "$@"
