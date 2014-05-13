
CXXFLAGS = -g -Wall -O -Wno-narrowing
LIBS = -lbfd -liberty -lz -lelf -lunwind-$(shell uname -p) -lunwind-ptrace

all: libbulkdbg.a bulkdbg

libbulkdbg.so.1: bulkdbg.cpp peekdata.cpp syscall_table.cpp
	$(CXX) -shared -Wl,-soname,libbulkdbg.so.1 -o libbulkdbg.so.1 \
		-fPIC $(CXXFLAGS) $^ $(LIBS)

libbulkdbg.a: bulkdbg.cpp peekdata.cpp syscall_table.cpp
	rm -f *.o *.a
	$(CXX) $(CXXFLAGS) $^ $(LIBS) -c
	ar rcs $@ *.o

bulkdbg: bulkdbg_main.cpp bulkdbg.cpp peekdata.cpp syscall_table.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

generate:
	./generate_syscall_table.pl > syscall_table.cpp

clean:
	rm -f bulkdbg libbulkdbg.so.1 *.a *.o

rpm: clean
	cd .. && tar cvz --exclude=.git -f /tmp/bulkdbg.tar.gz bulkdbg && \
		rpmbuild -ta /tmp/bulkdbg.tar.gz && \
		rm -f /tmp/bulkdbg.tar.gz
