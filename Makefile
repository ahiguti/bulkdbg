
CXXFLAGS = -g -Wall -O -Wno-narrowing
LIBS = -lbfd -liberty -lz -lelf -lunwind-$(shell uname -p) -lunwind-ptrace

bulkdbg: bulkdbg.cpp peekdata.cpp syscall_table.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

generate:
	./generate_syscall_table.pl > syscall_table.cpp

clean:
	rm -f bulkdbg

rpm: clean
	cd .. && tar cvz --exclude=.git -f /tmp/bulkdbg.tar.gz bulkdbg && \
		rpmbuild -ta /tmp/bulkdbg.tar.gz && \
		rm -f /tmp/bulkdbg.tar.gz
