
SUBDIRS = bulkdbg

all: rpms

clean:
	for i in $(SUBDIRS); do pushd $$i && make clean && popd; done
	rm -rf dist

rpms: clean
	mkdir -p dist/BUILD dist/RPMS dist/SOURCES dist/SPECS dist/SRPMS
	tar cvfz dist/bulkdbg.tar.gz --exclude=.git bulkdbg
	rpmbuild --define "_topdir `pwd`/dist" -ta dist/bulkdbg.tar.gz

installrpms: uninstallrpms rpms
	sudo rpm -U dist/RPMS/*/*.rpm

uninstallrpms:
	- sudo rpm -e bulkdbg
	- sudo rpm -e bulkdbg-debuginfo
