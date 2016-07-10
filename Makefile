# makefile dependencies
package_dir = package

# installation directories
prefix = /usr
bin_dir = $(prefix)/bin
sbin_dir = $(prefix)/sbin
config_dir = /etc/default
service_dir = /etc/init.d
share_dir = $(prefix)/share
man_dir = $(sharedir)/man
man1_dir = $(mandir)/man1

# main version of the program
VERSION = 3.3.3

# the target binary
target = iptables-loader.sh

# the name of the source package archive
source_pkg_ext = .tar.gz
source_pkg_name = iptables-loader
source_pkg = $(source_pkg_name)-$(VERSION)$(source_pkg_ext)



all: $(target)

### PROGRAM
# build the target
$(target):

# install the program into the current filesystem
.PHONY: install
install: all
	install $(target) $(DESTDIR)$(sbin_dir)/$(target:.sh=)
	install -m 640 iptables.conf $(DESTDIR)$(config_dir)/iptables
	install service/iptables.initd $(DESTDIR)$(service_dir)/iptables

### SOURCE PACKAGE
# build the package containing all source and the makefile
.PHONY: package-source
package-source: $(source_pkg)

# compress files into the source package
iptables-loader-%.tar.gz: $(target)
	@mkdir $(source_pkg_name)-$(VERSION)
	@mkdir $(source_pkg_name)-$(VERSION)/service
	@echo '  => Copying all program files into source archive'
	cp $(target) $(source_pkg_name)-$(VERSION)
	cp iptables.conf $(source_pkg_name)-$(VERSION)
	cp service/* $(source_pkg_name)-$(VERSION)/service/
	cp Makefile $(source_pkg_name)-$(VERSION)
	@echo '  => Compressing archive into "$@" ...'
	@tar czf $@ $(source_pkg_name)-$(VERSION)
	@rm -rf $(source_pkg_name)-$(VERSION)
	@echo '   ...OK'

.PHONY: clean-package-source
clean-package-source:
	rm -f $(source_pkg)

### DEBIAN PACKAGE
.PHONY: package-debian
package-debian: $(source_pkg)
	@echo '  => Moving source archive into Debian source format'
	@mv $< $(source_pkg_name)_$(VERSION).orig$(source_pkg_ext)
	@echo '  => Building debian package control folder'
	@$(MAKE) -C $(package_dir) package-debian
	@cp $(package_dir)/debian.tar.gz .
	@echo '  => Compressing DEBIAN package source ...'
	@tar czf $(source_pkg_name)-$(VERSION)_DEBIAN$(source_pkg_ext) debian.tar.gz $(source_pkg_name)_$(VERSION).orig$(source_pkg_ext) Makefile
	@rm debian.tar.gz
	@echo '   ...OK'
	@echo '  !> The Debian source archive is available at "$(source_pkg_name)-$(VERSION)_DEBIAN$(source_pkg_ext)"'

.PHONY: build-debian
build-debian: debian.tar.gz $(source_pkg_name)_$(VERSION).orig$(source_pkg_ext)
	@echo '  => Extract needed DEBIAN package files ...'
	@tar xzf $(source_pkg_name)_$(VERSION).orig$(source_pkg_ext)
	@tar xzf debian.tar.gz
	rm debian.tar.gz
	mv debian/ $(source_pkg_name)-$(VERSION)/
	cd $(source_pkg_name)-$(VERSION)/; debuild -us -uc

.PHONY: clean-package-debian
clean-package-debian:
	rm -f $(source_pkg_name)_$(VERSION).orig$(source_pkg_ext)
	rm -f $(source_pkg_name)-$(VERSION)_DEBIAN$(source_pkg_ext)
	$(MAKE) -C $(package_dir) clean-package-debian

.PHONY: clean-all
mrproper: clean clean-package-source clean-package-debian

clean:
