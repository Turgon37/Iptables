# CHANGE THIS TO THE NAME OF YOUR PROGRAM, THIS NAME WILL BE THE PACKAGE NAME
NAME=iptables-loader


DPKG_DEB=$(which dpkg-deb 2>/dev/null)
PACKAGE_ROOT=deb/$NAME
VERSION=$(grep --ignore-case 'version' $PACKAGE_ROOT/DEBIAN/control | grep -Eo '[0-9]+(\.[0-9]+)+')

umask 022

# SET HERE THE COMMAND TO RUN BEFORE MAKE THE PACKET
# SUCH AS cp BINARY FILE AND MAKE SOME CHMOD
cp ../iptables.conf $PACKAGE_ROOT/etc/default/iptables
chmod 640 $PACKAGE_ROOT/etc/default/iptables
cp ../iptables.sh $PACKAGE_ROOT/usr/sbin/$NAME
chmod 755 $PACKAGE_ROOT/usr/sbin/$NAME
chown -R root:root $PACKAGE_ROOT/*

# BUILDING
if [[ -n $DPKG_DEB ]]; then
  cd deb
  dpkg-deb --build $NAME
  mv $NAME.deb $NAME_$VERSION.deb
  echo 'The program is available with the last .deb package'
else
  tar cfz $NAME.tar.gz $PACKAGE_ROOT
  echo 'The program is available in the following archive'
fi
