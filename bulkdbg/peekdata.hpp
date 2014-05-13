
#ifndef BULKDBG_PEEKDATA_HPP
#define BULKDBG_PEEKDATA_HPP

#include <string>
#include <vector>
#include <map>

struct peekdata_ops;
typedef std::vector<unsigned long> peekdata_stack;

struct peekdata_data {
  peekdata_data() : popval(0), pid(-1), curop(0), exec_limit(256),
    string_limit(1024), trace_flag(false) { }
  std::auto_ptr<peekdata_ops> ops;
  peekdata_stack stk;
  unsigned long popval;
  int pid;
  size_t curop;
  std::vector<std::string> buffer;
  std::string err;
  size_t exec_limit;
  size_t string_limit;
  bool trace_flag;
  std::map<std::string, unsigned long> syms;
};

void peekdata_init(peekdata_data& dt, const std::string& s);
void peekdata_exec(peekdata_data& dt, unsigned long sp, int pid);

#endif

