package-debian: debian
	@tar czf debian.tar.gz debian/

.PHONY: clean-package-debian
clean-package-debian:
	rm -f debian.tar.gz

.PHONY: clean-all
clean-all: clean-package-debian