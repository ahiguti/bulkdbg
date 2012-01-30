
CXXFLAGS = -g -Wall -O
LIBS = -lbfd -liberty -lz -lelf

bulkdbg: bulkdbg.cpp syscall_table.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

generate:
	./generate_syscall_table.pl > syscall_table.cpp

clean:
	rm -f bulkdbg

