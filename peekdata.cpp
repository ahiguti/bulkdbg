
// vim: ai sw=2

/*
  bulkdbg - tool for debugging multiple processes or threads
  Copyright (c) Akira Higuchi
  All rights reserved.
*/

#include <sys/ptrace.h>
#include <memory>
#include <stdexcept>
#include <stdlib.h>
#include <stdio.h>
#include <functional>

#include "peekdata.hpp"

struct peekdata_op {
  virtual ~peekdata_op() { }
  virtual bool exec(peekdata_data& dt) = 0;
  peekdata_op() { }
private:
  peekdata_op(const peekdata_op&);
  peekdata_op& operator =(const peekdata_op&);
};

struct peekdata_ops {
  peekdata_ops() { }
  ~peekdata_ops() {
    for (size_t i = 0; i < ops.size(); ++i) {
      delete ops[i];
    }
  }
  std::vector<peekdata_op *> ops;
  std::vector<std::string> opsrcs;
private:
  peekdata_ops(const peekdata_ops&);
  peekdata_ops& operator =(const peekdata_ops&);
};

struct peekdata_op_ulong : peekdata_op {
  unsigned long value;
  peekdata_op_ulong(unsigned long v) : value(v) { }
  bool exec(peekdata_data& dt) {
    dt.stk.push_back(value);
    return true;
  }
};

template <typename f, bool is_divop> struct peekdata_op_binop : peekdata_op {
  bool exec(peekdata_data& dt) {
    if (dt.stk.size() < 2) {
      return false;
    }
    unsigned long v0 = dt.stk[dt.stk.size() - 2];
    unsigned long v1 = dt.stk[dt.stk.size() - 1];
    if (is_divop && v1 == 0) {
      return false;
    }
    unsigned long v = f()(v0, v1);
    dt.stk.push_back(v);
    return true;
  }
};

struct peekdata_op_peek : peekdata_op {
  bool exec(peekdata_data& dt) {
    if (dt.stk.empty()) {
      return false;
    }
    unsigned long addr = dt.stk[dt.stk.size() - 1];
    unsigned long val = ptrace(PTRACE_PEEKDATA, dt.pid, addr, 0);
    dt.stk.push_back(val);
    return true;
  }
};

struct peekdata_op_copy : peekdata_op {
  unsigned long offset;
  peekdata_op_copy(int o) : offset(o) { }
  bool exec(peekdata_data& dt) {
    if (dt.stk.size() <= offset) {
      return false;
    }
    unsigned long val = dt.stk[dt.stk.size() - offset - 1];
    dt.stk.push_back(val);
    return true;
  }
};

struct peekdata_op_pop : peekdata_op {
  unsigned long length;
  peekdata_op_pop(unsigned long len) : length(len) { }
  bool exec(peekdata_data& dt) {
    size_t sz = dt.stk.size();
    if (sz < length) {
      return false;
    }
    dt.popval = sz > 0 ? dt.stk[sz - 1] : 0;
    dt.stk.resize(sz - length);
    return true;
  }
};

template <bool conditional> struct peekdata_op_jmp : peekdata_op {
  long offset;
  peekdata_op_jmp(long o) : offset(o) { }
  bool exec(peekdata_data& dt) {
    if (conditional) {
      if (dt.popval == 0) {
	return true;
      }
    }
    dt.curop += offset;
    return true;
  }
};

struct peekdata_op_out_decimal : peekdata_op {
  bool exec(peekdata_data& dt) {
    if (dt.stk.empty()) {
      return false;
    }
    if (!dt.buf.empty()) {
      dt.buf.push_back('\t');
    }
    unsigned long val = dt.stk[dt.stk.size() - 1];
    char buf[32];
    size_t sz = snprintf(buf, sizeof(buf), "%lu", val);
    if (sz > 0) {
      dt.buf.insert(dt.buf.end(), buf, buf + sz);
    }
    return true;
  }
};

struct peekdata_op_out_hexadecimal : peekdata_op {
  bool exec(peekdata_data& dt) {
    if (dt.stk.empty()) {
      return false;
    }
    if (!dt.buf.empty()) {
      dt.buf.push_back('\t');
    }
    unsigned long val = dt.stk[dt.stk.size() - 1];
    char buf[32];
    size_t sz = snprintf(buf, sizeof(buf), "%lx", val);
    if (sz > 0) {
      dt.buf.insert(dt.buf.end(), buf, buf + sz);
    }
    return true;
  }
};

struct peekdata_op_out_string : peekdata_op {
  bool exec(peekdata_data& dt) {
    if (dt.stk.size() < 2) {
      return false;
    }
    if (!dt.buf.empty()) {
      dt.buf.push_back('\t');
    }
    unsigned long addr = dt.stk[dt.stk.size() - 2];
    unsigned long orig_len = dt.stk[dt.stk.size() - 1];
    unsigned long len = orig_len;
    if (orig_len > dt.string_limit) {
      len = dt.string_limit;
    }
    char buf[sizeof(long)];
    for (unsigned long i = 0; i < len; i += sizeof(long)) {
      *reinterpret_cast<unsigned long *>(buf) = ptrace(PTRACE_PEEKDATA,
	dt.pid, addr + i, 0);
      if (i + sizeof(long) <= len) {
	dt.buf.insert(dt.buf.end(), buf, buf + sizeof(long));
      } else {
	dt.buf.insert(dt.buf.end(), buf, buf + (len - i));
      }
    }
    if (orig_len > dt.string_limit) {
      dt.buf += "...";
    }
    return true;
  }
};

static void
make_peekdata_ops(peekdata_data& dt, const std::string& s)
{
  std::auto_ptr<peekdata_ops> pops(new peekdata_ops());
  std::string tok;
  for (size_t i = 0; i < s.size(); ++i) {
    char ch = s[i];
    if (ch == ',') {
      pops->opsrcs.push_back(tok);
      tok.clear();
    } else {
      tok.push_back(ch);
    }
  }
  pops->opsrcs.push_back(tok);
  for (size_t i = 0; i < pops->opsrcs.size(); ++i) {
    const std::string& src = pops->opsrcs[i];
    if (src.empty()) {
      dt.err = "invalid op [" + src + "]";
      return;
    }
    peekdata_op *op = 0;
    if (src == "ld") {
      op = new peekdata_op_peek();
    } else if (src == "add") {
      op = new peekdata_op_binop<std::plus<unsigned long>, false>();
    } else if (src == "sub") {
      op = new peekdata_op_binop<std::minus<unsigned long>, false>();
    } else if (src == "mul") {
      op = new peekdata_op_binop<std::multiplies<unsigned long>, false>();
    } else if (src == "div") {
      op = new peekdata_op_binop<std::divides<unsigned long>, true>();
    } else if (src == "mod") {
      op = new peekdata_op_binop<std::modulus<unsigned long>, true>();
    } else if (src == "and") {
      op = new peekdata_op_binop<std::bit_and<unsigned long>, false>();
    } else if (src == "or") {
      op = new peekdata_op_binop<std::bit_or<unsigned long>, false>();
    } else if (src == "xor") {
      op = new peekdata_op_binop<std::bit_xor<unsigned long>, false>();
    } else if (src == "land") {
      op = new peekdata_op_binop<std::logical_and<unsigned long>, false>();
    } else if (src == "lor") {
      op = new peekdata_op_binop<std::logical_or<unsigned long>, false>();
    } else if (src == "eq") {
      op = new peekdata_op_binop<std::equal_to<unsigned long>, false>();
    } else if (src == "ne") {
      op = new peekdata_op_binop<std::not_equal_to<unsigned long>, false>();
    } else if (src == "gt") {
      op = new peekdata_op_binop<std::greater<unsigned long>, false>();
    } else if (src == "ge") {
      op = new peekdata_op_binop<std::greater_equal<unsigned long>, false>();
    } else if (src == "lt") {
      op = new peekdata_op_binop<std::less<unsigned long>, false>();
    } else if (src == "le") {
      op = new peekdata_op_binop<std::less_equal<unsigned long>, false>();
    } else if (src == "outd") {
      op = new peekdata_op_out_decimal();
    } else if (src == "outh") {
      op = new peekdata_op_out_hexadecimal();
    } else if (src == "outs") {
      op = new peekdata_op_out_string();
    } else if (src.substr(0, 2) == "cp") {
      op = new peekdata_op_copy(strtoul(src.c_str() + 2, 0, 0));
    } else if (src.substr(0, 2) == "po") {
      op = new peekdata_op_pop(strtoul(src.c_str() + 2, 0, 0));
    } else if (src[0] == 'j') {
      op = new peekdata_op_jmp<false>(strtol(src.c_str() + 1, 0, 0));
    } else if (src.substr(0, 2) == "cj") {
      op = new peekdata_op_jmp<true>(strtol(src.c_str() + 2, 0, 0));
    } else if (src[0] >= '0' && src[0] <= '9') {
      op = new peekdata_op_ulong(strtoul(src.c_str(), 0, 0));
    } else if (src == "tr") {
      dt.trace_flag = true;
    } else if (src.substr(0, 4) == "elim") {
      dt.exec_limit = strtoul(src.c_str() + 4, 0, 0);
    } else if (src.substr(0, 4) == "slim") {
      dt.string_limit = strtoul(src.c_str() + 4, 0, 0);
    } else {
      dt.err = "invalid op [" + src + "]";
    }
    if (op != 0) {
      pops->ops.push_back(op);
    }
  }
  dt.ops = pops;
}

void peekdata_init(peekdata_data& dt, const std::string& s)
{
  dt.stk.clear();
  dt.popval = 0;
  dt.pid = -1;
  dt.curop = 0;
  dt.buf.clear();
  dt.err.clear();
  dt.exec_limit = 256;
  dt.string_limit = 1024;
  dt.trace_flag = false;
  make_peekdata_ops(dt, s);
}

static void peekdata_trace_one(peekdata_data& dt)
{
  fprintf(stderr, "%lu\t%s\t=>\t[", dt.curop,
    dt.ops->opsrcs[dt.curop].c_str());
  for (size_t i = 0; i < dt.stk.size(); ++i) {
    if (i != 0) {
      fprintf(stderr, " ");
    }
    fprintf(stderr, "%lx", dt.stk[i]);
  }
  fprintf(stderr, "]\n");
}

void peekdata_exec(peekdata_data& dt, unsigned long sp, int pid)
{
  dt.popval = 0;
  dt.pid = pid;
  dt.curop = 0;
  dt.buf.clear();
  dt.err.clear();
  dt.stk.clear();
  dt.stk.push_back(sp);
  const size_t exec_limit = dt.exec_limit;
  size_t exec_cnt = 0;
  std::vector<peekdata_op *> const& ops = dt.ops->ops;
  if (!dt.trace_flag) {
    while (dt.curop < ops.size() && exec_cnt < exec_limit) {
      if (!ops[dt.curop]->exec(dt)) {
	break;
      }
      ++dt.curop;
      ++exec_cnt;
    }
  } else {
    while (dt.curop < ops.size() && exec_cnt < exec_limit) {
      const bool r = ops[dt.curop]->exec(dt);
      peekdata_trace_one(dt);
      if (!r) {
	fprintf(stderr, "break at %zu, op=[%s]\n", dt.curop,
	  dt.ops->opsrcs[dt.curop].c_str());
	break;
      }
      ++dt.curop;
      ++exec_cnt;
    }
  }
}

