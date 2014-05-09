
// vim: ai sw=2

/*
  bulkdbg - tool for debugging multiple processes or threads
  Copyright (c) Akira Higuchi
  All rights reserved.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <limits.h>
#include <string.h>
#include <sched.h>
#include <dirent.h>
#include <list>
#include <vector>
#include <map>
#include <string>
#include <memory>
#include <bfd.h>
#include <algorithm>
#include <libelf.h>
#include <cxxabi.h>

#include <linux/version.h>
#include <asm/unistd.h>

#include <libunwind-ptrace.h>

#include "syscall_table.hpp"
#include "peekdata.hpp"

#define DBG(v, x) if (cnf.debug_level >= v) { x; }

#if defined(__i386__)
#define BULKDBG_IP eip
#define BULKDBG_SP esp
#define BULKDBG_FP ebp
#define BULKDBG_ORIG_A orig_eax
#define BULKDBG_A eax
#define BULKDBG_ARG1 ebx
#define BULKDBG_ARG2 ecx
#define BULKDBG_ARG3 edx
#define BULKDBG_ARG4 esi
#define BULKDBG_ARG5 edi
#define BULKDBG_ARG6 ebp
#elif defined(__x86_64__)
#define BULKDBG_IP rip
#define BULKDBG_SP rsp
#define BULKDBG_FP rbp
#define BULKDBG_ORIG_A orig_rax
#define BULKDBG_A rax
#define BULKDBG_ARG1 rdi
#define BULKDBG_ARG2 rsi
#define BULKDBG_ARG3 rdx
#define BULKDBG_ARG4 r10
#define BULKDBG_ARG5 r8
#define BULKDBG_ARG6 r9
#else
#error "unsupported cpu arch"
#endif

#if !defined(__linux__)
#error "unsupported os"
#endif

struct syscall_info {
  const char *name;
};
typedef std::vector<syscall_info> syscall_info_arr_type;

struct examine_entry {
  examine_entry() : offset(0) { }
  std::string upfuncname;
  std::string funcname;
  size_t offset;
  peekdata_data *pdata; /* FIXME: leaks */
};

#if 0
static int debug_level = 0;
static int group_bt = 0;
static int procstat = 0;
static int same_map = 0;
static int trace_unw = 100;
static int trace_fp = 0;
static int trace_sp = 0;
static int dump_sp = 0;
static int dump_regs = 0;
static int do_strace = 0;
static int show_offset = 0;
static int show_offset_hex = 0;
static int show_calls = 1;
static int demangle_cxx = 0;
static int show_threads = 0;
static int hex_pid = 0;
static int num_repeat = 1;
static int repeat_delay = 0;
static int show_syscall = 0;
static std::vector<examine_entry> exdata_list;
static std::map<std::string, unsigned long> peekdata_syms;
static std::string calltrace_delim = ":";
static syscall_info_arr_type syscall_info_arr;
static syscall_info_arr_type socketcall_info_arr;
#endif

#if 1
struct bulkdbg_conf {
public:
  int debug_level;
  int group_bt;
  int procstat;
  int same_map;
  int trace_unw;
  int trace_fp;
  int trace_sp;
  int dump_sp;
  int dump_regs;
  int do_strace;
  int show_offset;
  int show_offset_hex;
  int show_calls;
  int demangle_cxx;
  int show_threads;
  int hex_pid;
  int num_repeat;
  int repeat_delay;
  int show_syscall;
  std::vector<examine_entry> exdata_list;
  std::map<std::string, unsigned long> peekdata_syms;
  std::string calltrace_delim;
  syscall_info_arr_type syscall_info_arr;
  syscall_info_arr_type socketcall_info_arr;
public:
  bulkdbg_conf()
  {
    debug_level = 0;
    group_bt = 0;
    procstat = 0;
    same_map = 0;
    trace_unw = 100;
    trace_fp = 0;
    trace_sp = 0;
    dump_sp = 0;
    dump_regs = 0;
    do_strace = 0;
    show_offset = 0;
    show_offset_hex = 0;
    show_calls = 1;
    demangle_cxx = 0;
    show_threads = 0;
    hex_pid = 0;
    num_repeat = 1;
    repeat_delay = 0;
    show_syscall = 0;
    /* exdata_list; */
    /* peekdata_syms; */
    calltrace_delim = ":";
    /* syscall_info_arr; */
    /* socketcall_info_arr; */
  }
private:
  bulkdbg_conf(const bulkdbg_conf&);
  bulkdbg_conf& operator =(const bulkdbg_conf&);
};
#endif

struct scoped_bfd {
  scoped_bfd(const char *filename)
    : abfd(bfd_openr(filename, 0)) { }
  ~scoped_bfd() {
    if (abfd != 0) {
      bfd_close(abfd);
    }
  }
  bfd *get() { return abfd; }
 private:
  bfd *abfd;
 private:
  scoped_bfd(const scoped_bfd&);
  scoped_bfd& operator =(const scoped_bfd&);
};

struct symbol_ent {
  unsigned long addr;
  std::string name;
  operator unsigned long() const { return addr; }
  symbol_ent() : addr(0) { }
};

struct symbol_table {
  typedef std::vector<symbol_ent> symbols_type;
  symbols_type symbols;
  unsigned long text_vma;
  unsigned long text_size;
  bool is_relative;
  symbol_table() : text_vma(0), text_size(0), is_relative(false) { }
};

struct auto_fp {
  explicit auto_fp(FILE *fp) : fp(fp) { }
  ~auto_fp() { if (fp) { fclose(fp); } }
  operator FILE *() { return fp; }
private:
  FILE *fp;
  auto_fp(const auto_fp&);
  auto_fp& operator =(const auto_fp&);
};

static bool check_shlib(const std::string& fn)
{
  auto_fp fp(fopen(fn.c_str(), "r"));
  if (fp == 0) {
    return false;
  }
  elf_version(EV_CURRENT);
  Elf *elf = elf_begin(fileno(fp), ELF_C_READ, NULL);
  if (elf == 0) {
    return false;
  }
  unsigned long vaddr = 0;
  #if defined(__i386__)
  Elf32_Ehdr *const ehdr = elf32_getehdr(elf);
  Elf32_Phdr *const phdr = elf32_getphdr(elf);
  #else
  Elf64_Ehdr *const ehdr = elf64_getehdr(elf);
  Elf64_Phdr *const phdr = elf64_getphdr(elf);
  #endif
  if (ehdr == 0 || phdr == 0) {
    /* TODO: support Elf32 on x86_64 */
    return false;
  }
  const int num_phdr = ehdr->e_phnum;
  for (int i = 0; i < num_phdr; ++i) {
    #if defined(__i386__)
    Elf32_Phdr *const p = phdr + i;
    #else
    Elf64_Phdr *const p = phdr + i;
    #endif
    if (p->p_type == PT_LOAD && (p->p_flags & 1) != 0) {
      vaddr = p->p_vaddr;
      break;
    }
  }
  elf_end(elf);
  return vaddr == 0;
}

static int load_symbol_table(bulkdbg_conf& cnf, const std::string& fn,
  symbol_table& st, unsigned long addr_begin)
{
  std::string dbg_fn = "/usr/lib/debug" + fn + ".debug";
  const char *filename = 0;
  if (access(dbg_fn.c_str(), R_OK) == 0) {
    filename = dbg_fn.c_str();
  } else {
    filename = fn.c_str();
  }
  st.is_relative = check_shlib(filename);
  scoped_bfd abfd(filename);
  if (abfd.get() == 0) {
    DBG(1, fprintf(stderr, "failed to open %s\n", filename));
    return -1;
  }
  bfd_check_format(abfd.get(), bfd_object);
  if ((bfd_get_file_flags (abfd.get()) & HAS_SYMS) == 0) {
    DBG(1, fprintf(stderr, "no symbol\n"));
    return -1;
  }
  asection *const text_sec = bfd_get_section_by_name(abfd.get(), ".text");
  if (text_sec) {
    st.text_vma = text_sec->vma;
    st.text_size = text_sec->size;
  }

  unsigned int size = 0;
  void *syms = 0;
  int dynamic = 0;
  long symcnt = bfd_read_minisymbols(abfd.get(), 0, &syms, &size);
  if (symcnt == 0) {
    symcnt = bfd_read_minisymbols(abfd.get(), 1, &syms, &size);
    dynamic = 1;
  }
  DBG(10, fprintf(stderr, "%ld symbols, dynamic=%d, vma=%lx sz=%lx\n",
    symcnt, dynamic,
    (unsigned long)text_sec->vma, (unsigned long)text_sec->size));

  asymbol *store = bfd_make_empty_symbol(abfd.get());
  if (store == 0) {
    DBG(10, fprintf(stderr, "make_empty_symbol\n"));
    return -1;
  }
  bfd_byte *p = (bfd_byte *)syms;
  bfd_byte *pend = p + symcnt * size;
  for (; p < pend; p += size) {
    asymbol *sym = 0;
    sym = bfd_minisymbol_to_symbol(abfd.get(), dynamic, p, store);
    symbol_info sinfo;
    bfd_get_symbol_info(abfd.get(), sym, &sinfo);
    const std::string symstr(sinfo.name);
    DBG(10, fprintf(stderr, "%s %lx f=%x t=%c\n", sinfo.name, (long)sinfo.value,
      (int)sym->flags, sinfo.type));
    if (!cnf.peekdata_syms.empty() &&
      cnf.peekdata_syms.find(symstr) != cnf.peekdata_syms.end()) {
      unsigned long absval = sinfo.value;
      if (st.is_relative) {
	absval += addr_begin;
      }
      cnf.peekdata_syms[symstr] = absval;
      DBG(10, fprintf(stderr, "peekdata sym found %s %lx\n", symstr.c_str(),
	absval));
    }
    if ((sym->flags & BSF_FUNCTION) == 0) {
      continue;
    }
    if (sinfo.type != 'T' && sinfo.type != 't' && sinfo.type != 'W' &&
      sinfo.type != 'w' && sinfo.type != 'B' && sinfo.type != 'b') {
      continue;
    }
    symbol_ent e;
    e.addr = sinfo.value;
    e.name = symstr;
    st.symbols.push_back(e);
  }
  std::sort(st.symbols.begin(), st.symbols.end(), std::less<unsigned long>());
  DBG(2, fprintf(stderr, "symbols for %s loaded %d\n", filename,
    (int)st.symbols.size()));
  return 0;
}

struct symbol_table_map {
  symbol_table_map() {
  }
  ~symbol_table_map() {
    for (m_type::iterator i = m.begin(); i != m.end(); ++i) {
      delete i->second;
    }
  }
  symbol_table *get(bulkdbg_conf& cnf, const std::string& path,
    unsigned long addr_begin) {
    m_type::iterator i = m.find(path);
    if (i != m.end()) {
      return i->second;
    }
    std::auto_ptr<symbol_table> p(new symbol_table);
    if (load_symbol_table(cnf, path, *p, addr_begin) != 0 ||
      p->symbols.empty()) {
      p.reset();
    }
    m[path] = p.get(); /* can be 0 */
    return p.release();
  }
  bool empty() const { return m.empty(); }
 private:
  typedef std::map<std::string, symbol_table *> m_type;
  m_type m;
 private:
  symbol_table_map(const symbol_table_map&);
  symbol_table_map& operator =(const symbol_table_map&);
};

static const symbol_ent *find_symbol(const symbol_table& st,
  unsigned long addr, bool& is_text_r, unsigned long& pos_r,
    unsigned long& offset_r)
{
  is_text_r = false;
  pos_r = 0;
  offset_r = 0;
  const symbol_table::symbols_type& ss = st.symbols;
  symbol_table::symbols_type::const_iterator j =
    std::upper_bound(ss.begin(), ss.end(), addr);
  if (j != ss.begin()) {
    --j;
  } else {
    return 0;
  }
  if (j == ss.end()) {
    return 0;
  }
  is_text_r = (*j >= st.text_vma && *j < st.text_vma + st.text_size);
  pos_r = j - ss.begin();
  offset_r = addr - *j;
  return &*j;
}

static int ptrace_attach_proc(bulkdbg_conf& cnf, int pid)
{
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
    DBG(1, perror("ptrace(PTRACE_ATTACH)"));
    return -1;
  }
  int st = 0;
  const pid_t v = waitpid(pid, &st, __WALL | WUNTRACED);
  if (v < 0) {
    DBG(1, perror("waitpid"));
    return -1;
  }
  return 0;
}

static int ptrace_detach_proc(bulkdbg_conf& cnf, int pid)
{
  if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
    DBG(1, perror("ptrace(PTRACE_DETACH)"));
    return -1;
  }
  return 0;
}

struct proc_map_ent {
  unsigned long addr_begin;
  unsigned long addr_size;
  unsigned long offset;
  std::string path;
  symbol_table *stbl;
  bool relative : 1;
  bool is_vdso : 1;
  symbol_ent nosym_symbol;
  operator unsigned long() const { return addr_begin; } /* for comparison */
  proc_map_ent() : addr_begin(0), addr_size(0), offset(0), stbl(0),
    relative(false), is_vdso(false) { }
};

struct proc_info {
  typedef std::vector<proc_map_ent> maps_type;
  maps_type maps;
};

static void read_proc_map_ent(bulkdbg_conf& cnf, char *line, proc_info& pinfo,
  symbol_table_map& stmap)
{
  char *t1 = strchr(line, ' ');
  if (!t1) { return; }
  char *t2 = strchr(t1 + 1, ' ');
  if (!t2) { return; }
  char *t3 = strchr(t2 + 1, ' ');
  if (!t3) { return; }
  char *t4 = strchr(t3 + 1, ' ');
  if (!t4) { return; }
  char *t5 = strchr(t4 + 1, ' ');
  if (!t5) { return; }
  while (t5[1] == ' ') { ++t5; }
  char *t6 = strchr(t5 + 1, '\n');
  if (!t6) { return; }
  *t1 = *t2 = *t3 = *t4 = *t5 = *t6 = '\0';
  if (t2 - t1 == 5 && t2[-2] != 'x') {
    return;
  }
  unsigned long a0 = 0, a1 = 0;
  sscanf(line, "%lx-%lx", &a0, &a1);
  DBG(10, fprintf(stderr, "[%lx] [%lx] [%s] [%s]\n",
    a0, a1 - a0, t2 + 1, t5 + 1));
  proc_map_ent e;
  e.addr_begin = a0;
  e.addr_size = a1 - a0;
  e.offset = atol(t2 + 1);
  e.path = std::string(t5 + 1);
  if (e.path == "[vdso]" || e.path == "[vsyscall]") {
    e.is_vdso = true;
  } else {
    e.stbl = stmap.get(cnf, e.path, e.addr_begin);
    e.relative = e.stbl != 0 ? e.stbl->is_relative : false;
  }
  std::string bpath = e.path;
  std::string::size_type sl = bpath.rfind('/');
  if (sl != bpath.npos) {
    bpath = bpath.substr(sl + 1);
  }
  if (bpath.empty()) {
    // bpath = "?";
  }
  // fprintf(stderr, "bpath=%s\n", bpath.c_str());
  e.nosym_symbol.name = "<" + bpath + ">";
  e.nosym_symbol.addr = e.addr_begin;
  pinfo.maps.push_back(e);
}

static void read_maps(bulkdbg_conf& cnf, int pid, proc_info& pi,
  symbol_table_map& stmap)
{
  char fn[PATH_MAX];
  char buf[4096];
  snprintf(fn, sizeof(fn), "/proc/%d/maps", pid);
  auto_fp fp(fopen(fn, "r"));
  if (fp == 0) {
    return;
  }
  while (fgets(buf, sizeof(buf), fp) != 0) {
    read_proc_map_ent(cnf, buf, pi, stmap);
  }
  #if 0
  std::sort(pi.maps.begin(), pi.maps.end(), std::less<unsigned long>());
    /* already sorted? */
  #endif
}

#if 0
static int get_ipreg_procstat(int pid, proc_info& pinfo,
  std::vector<unsigned long>& vals_r)
{
  char fn[1024];
  char buf[4096];
  snprintf(fn, sizeof(fn), "/proc/%d/stat", pid);
  auto_fp fp(fopen(fn, "r"));
  if (fp == 0) {
    return 1;
  }
  if (fgets(buf, sizeof(buf), fp) != 0) {
    buf[4095] = 0;
    char *p = strrchr(buf, ')');
    if (p != 0) {
      int cnt = 0;
      for (; *p != 0 && cnt < 28; ++p) {
	if (*p == ' ') {
	  ++cnt;
	}
      }
      char *q = p;
      for (; *q != 0 && *q != ' '; ++q) { }
      if (*q != 0) {
	*q = 0;
	unsigned long v = strtoul(p, 0, 10);
	if (v != ULONG_MAX) {
	  vals_r.push_back(v);
	}
      }
    }
  }
  return vals_r.empty();
}
#endif

static int get_user_regs(bulkdbg_conf& cnf, int pid, user_regs_struct& regs)
{
  int count = 100;
  while (1) {
    int e = ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if (e != 0) {
      if (errno == ESRCH && count-- > 0) {
        /* i dont know why waitpid() does not work for threads */
        sched_yield();
        continue;
      }
      DBG(1, fprintf(stderr, "pid=%d\n", pid));
      DBG(1, perror("ptrace(PTRACE_GETREGS)"));
      return -1;
    }
    break;
  }
  return 0;
}

static const symbol_ent *pinfo_find_symbol(bulkdbg_conf& cnf,
  const proc_info& pinfo, unsigned long addr, unsigned long& offset_r)
{
  offset_r = 0;
  proc_info::maps_type::const_iterator i = std::upper_bound(
    pinfo.maps.begin(), pinfo.maps.end(), addr);
  DBG(10, fprintf(stderr, "%lx maps %u of %u\n", addr,
    unsigned(i - pinfo.maps.begin()), unsigned(pinfo.maps.size())));
  if (i != pinfo.maps.begin()) {
    --i;
  } else {
    i = pinfo.maps.end();
  }
  if (i == pinfo.maps.end()) {
    /* not found */
    DBG(3, fprintf(stderr, "%lx notfound1\n", addr));
  } else if (addr >= i->addr_begin + i->addr_size) {
    /* out of range */
    DBG(3, fprintf(stderr, "%lx notfound2 [%lx %lx]\n", addr, i->addr_begin,
      i->addr_begin + i->addr_size));
  } else if (i->stbl == 0) {
    /* no symbol */
    DBG(3, fprintf(stderr, "%lx notfound3\n", addr));
    offset_r = addr - i->addr_begin;
    return &i->nosym_symbol;
  } else {
    unsigned long a = addr;
    const symbol_table& st = *i->stbl;
    if (i->relative) {
      a -= i->addr_begin;
    }
    unsigned long pos = 0;
    unsigned long offset = 0;
    bool is_text = false;
    const symbol_ent *const e = find_symbol(st, a, is_text, pos, offset);
    if (e != 0 && is_text) {
      DBG(3, fprintf(stderr, "%lx found %s (%lx - %lx) %s (%luth of %lu)\n",
        addr, e->name.c_str(), i->addr_begin, i->addr_begin + i->addr_size,
        i->path.c_str(), pos, (unsigned long)st.symbols.size()));
      offset_r = offset;
      return e;
    } else {
      DBG(3, fprintf(stderr, "%lx notfound %s\n", addr, i->path.c_str()));
      offset_r = addr - i->addr_begin;
      return &i->nosym_symbol;
    }
  }
  return 0;
}

const syscall_info *find_syscall(bulkdbg_conf& cnf,
  const user_regs_struct& regs)
{
  const int syscall_num = regs.BULKDBG_ORIG_A;
  const syscall_info *sinfo = 0;
  if (syscall_num >= 0 && (size_t)syscall_num < cnf.syscall_info_arr.size()) {
    sinfo = &cnf.syscall_info_arr[syscall_num];
  }
  #ifdef __i386__
  if (syscall_num == __NR_socketcall) {
    const int socketcall_num = regs.ebx;
    if (socketcall_num >= 0 &&
      (size_t)socketcall_num < socketcall_info_arr.size()) {
      sinfo = &socketcall_info_arr[socketcall_num];
    }
  }
  #endif
  return sinfo;
}

static std::string ulong_to_str_hex(unsigned long v)
{
  char buf[64];
  if (sizeof(v) == 4) {
    snprintf(buf, sizeof(buf), ":%08lx ", v);
  } else {
    snprintf(buf, sizeof(buf), ":%016lx ", v);
  }
  return buf;
}

static std::string cxxdemangle(const char *s)
{
  int status = 0;
  char *p = abi::__cxa_demangle(s, 0, 0, &status);
  if (p != 0) {
    std::string r(p);
    free(p);
    return r;
  }
  return std::string(s);
}

static std::string examine_symbols(bulkdbg_conf& cnf, const proc_info& pinfo,
   const user_regs_struct& regs, const std::vector<unsigned long>& vals,
   size_t maxlen, const std::string& edata)
{
  std::string rstr;
  if (cnf.show_calls == 0) {
    maxlen = 0;
  }
  if (cnf.show_syscall) {
    const int syscall_num = regs.BULKDBG_ORIG_A;
    if (syscall_num < 0) {
      rstr += "-";
    } else {
      char buf[32];
      snprintf(buf, 32, "%d", syscall_num);
      rstr += buf;
    }
  }
  /* vals[0] is ip */
  for (size_t i = 0; i < std::min(vals.size(), maxlen); ++i) {
    unsigned long addr = vals[i];
    unsigned long offset = 0;
    const symbol_ent *e = pinfo_find_symbol(cnf, pinfo, addr, offset);
    if (e != 0) {
      const syscall_info *sinfo = 0;
      if (i == 0) {
	#ifdef __i386__
	if (i == 0 && e->name == "_dl_sysinfo_int80" && offset == 2) { // TODO
	  sinfo = find_syscall(cnf, regs);
	}
	#else
	sinfo = find_syscall(cnf, regs);
	#endif
      }
#if 0
      if (offset != 0) {
#endif
	if (!rstr.empty()) {
	  rstr += cnf.calltrace_delim;
	}
	if (sinfo != 0) {
	  rstr += std::string(sinfo->name);
	} else {
	  if (cnf.demangle_cxx) {
	    rstr += cxxdemangle(e->name.c_str());
	  } else {
	    rstr += e->name;
	  }
	}
	if (cnf.show_offset) {
	  char buf[32];
	  if (cnf.show_offset_hex) {
	    snprintf(buf, 32, "(%lx+%.*lx)", addr-offset, cnf.show_offset,
	      offset);
	  } else {
	    snprintf(buf, 32, "(%lx+%.*ld)", addr-offset, cnf.show_offset,
	      offset);
	  }
	  rstr += std::string(buf);
	}
#if 0
      } else {
	if (!rstr.empty()) {
	  rstr += calltrace_delim;
	}
	rstr += "offset0"; // FIXME
      }
#endif
#if 0
    } else if (offset != 0) {
      /* vdso */
      if (i == 0 && offset == 0x410) { // TODO
        const syscall_info *sinfo = find_syscall(regs);
	if (sinfo != 0) {
	  if (!rstr.empty()) {
	    rstr += calltrace_delim;
	  }
	  rstr += "(" + std::string(sinfo->name) + ")";
	}
      }
#endif
    } else {
      char buf[32];
      snprintf(buf, 32, "(%lx)", addr);
      if (!rstr.empty()) {
	rstr += cnf.calltrace_delim;
      }
      rstr += std::string(buf);
    }
  }
  if (!edata.empty()) {
    if (!rstr.empty()) {
      rstr += "\t";
    }
    rstr += edata;
  }
  return rstr;
}

#if 0
static void dump_stack(bulkdbg_conf& cnf, int pid, const proc_info& pinfo,
  unsigned long sp, const std::vector<unsigned long>& vals, size_t maxlen)
{
  for (size_t i = 1; i < std::min(vals.size(), maxlen + 1);
    ++i, sp += sizeof(long)) {
    unsigned long val = vals[i];
    std::string sym;
    unsigned long offset = 0;
    const symbol_ent *e = pinfo_find_symbol(cnf, pinfo, val, offset);
    if (e != 0) {
      if (sizeof(val) == 4) {
        printf("%d - %08lx %08lx %s+%lx\n",
          pid, sp, val, e->name.c_str(), offset);
      } else {
        printf("%d - %016lx %016lx %s+%lx\n",
          pid, sp, val, e->name.c_str(), offset);
      }
    } else {
      if (sizeof(val) == 4) {
        printf("%d - %08lx %08lx\n", pid, sp, val);
      } else {
        printf("%d - %016lx %016lx\n", pid, sp, val);
      }
    }
  }
}
#endif

static std::string get_user_regs_str(int pid, const user_regs_struct& regs)
{
  std::string s;
  #define DUMP_REG(x) s += std::string(#x) + ulong_to_str_hex(regs.x)
  #if defined(__i386__)
  DUMP_REG(eax);
  DUMP_REG(ebx);
  DUMP_REG(ecx);
  DUMP_REG(edx);
  DUMP_REG(esi);
  DUMP_REG(edi);
  DUMP_REG(ebp);
  DUMP_REG(esp);
  DUMP_REG(eip);
  DUMP_REG(eflags);
  DUMP_REG(orig_eax);
  DUMP_REG(xcs);
  DUMP_REG(xss);
  DUMP_REG(xds);
  DUMP_REG(xes);
  DUMP_REG(xfs);
  DUMP_REG(xgs);
  #elif defined(__x86_64__)
  DUMP_REG(rax);
  DUMP_REG(rbx);
  DUMP_REG(rcx);
  DUMP_REG(rdx);
  DUMP_REG(rsi);
  DUMP_REG(rdi);
  DUMP_REG(rbp);
  DUMP_REG(rsp);
  DUMP_REG(r8);
  DUMP_REG(r9);
  DUMP_REG(r10);
  DUMP_REG(r11);
  DUMP_REG(r12);
  DUMP_REG(r13);
  DUMP_REG(r14);
  DUMP_REG(r15);
  DUMP_REG(rip);
  DUMP_REG(eflags);
  DUMP_REG(orig_rax);
  DUMP_REG(cs);
  DUMP_REG(ss);
  DUMP_REG(ds);
  DUMP_REG(es);
  DUMP_REG(fs);
  DUMP_REG(gs);
  #endif
  #undef DUMP_REGS
  s.resize(s.size() - 1);
  return s;
}

static void dump_user_regs(bulkdbg_conf& cnf, int pid,
  const user_regs_struct& regs)
{
  std::string s = get_user_regs_str(pid, regs);
  if (cnf.hex_pid) {
    printf("%x\t%s\n", pid, s.c_str());
  } else {
    printf("%d\t%s\n", pid, s.c_str());
  }
}

static int get_stack_trace_unw(bulkdbg_conf& cnf, unw_addr_space_t unw_as,
  struct UPT_info *saved_ui, int pid, proc_info& pinfo, unsigned int maxlen,
  const user_regs_struct& regs, std::vector<unsigned long>& vals_r,
  std::string& edata_r)
{
  struct UPT_info *ui = saved_ui;
  if (saved_ui == 0) {
    ui = (struct UPT_info *)_UPT_create(pid);
  }
  unw_cursor_t cur;
  std::string upfn;
  do {
    if (unw_init_remote(&cur, unw_as, ui) < 0) {
      DBG(0, fprintf(stderr, "unw_init_remote failed\n"));
      break;
    }
    unw_word_t ip_prev = 0;
    for (unsigned int i = 0; i < maxlen; ++i) {
      unw_word_t ip, sp;
      if (unw_get_reg(&cur, UNW_REG_IP, &ip) < 0) {
	DBG(0, fprintf(stderr, "unw_get_reg ip failed\n"));
	break;
      }
      DBG(3, fprintf(stderr, "ip=%lx\n", ip));
      if (ip_prev == ip || ip == 0) {
	break;
      }
      unsigned long offset = 0;
      const symbol_ent *e = pinfo_find_symbol(cnf, pinfo, ip, offset);
      ip_prev = ip;
      vals_r.push_back(ip);
      if (unw_get_reg(&cur, UNW_REG_SP, &sp) < 0) {
	DBG(0, fprintf(stderr, "unw_get_reg sp failed\n"));
	break;
      }
      if (e != 0 && e->name.empty()) {
	/* module not found. dont trace futher. */
	break;
      }
      if (!cnf.exdata_list.empty()) {
	if (e != 0) {
	  for (size_t i = 0; i < cnf.exdata_list.size(); ++i) {
	    examine_entry& ee = cnf.exdata_list[i];
	    if (ee.funcname == e->name &&
	      (ee.offset == 0 || ee.offset == offset) &&
	      (ee.upfuncname.empty() || ee.upfuncname == upfn)) {
	      for (std::map<std::string, unsigned long>::iterator i
		= ee.pdata->syms.begin(); i != ee.pdata->syms.end(); ++i) {
		i->second = cnf.peekdata_syms[i->first];
	      }
	      peekdata_exec(*ee.pdata, sp, pid);
	      if (!ee.pdata->err.empty()) {
		DBG(0, fprintf(stderr, "peekdata failed: %s\n",
		  ee.pdata->err.c_str()));
	      } else {
		const std::vector<std::string>& buf = ee.pdata->buffer;
		for (size_t i = 0; i < buf.size(); ++i) {
		  if (!edata_r.empty()) {
		    edata_r += "\t";
		  }
		  edata_r += buf[i];
		}
	      }
	    }
	  }
	  upfn = e->name;
	}
      }
      /* dont use unw_get_proc_name because it's too slow */
      #if 0
      {
	char buf[256];
	unw_word_t off = 0;
	unw_get_proc_name(&cur, buf, sizeof(buf), &off);
	//  DBG(0, fprintf(stderr, "unw_get_proc_name failed\n"));
	//  break;
	//}
	// printf("IP %s(%lx)\n", buf, off);
      }
      #endif
      #if 0
      unw_proc_info_t pi;
      if (unw_get_proc_info(&cur, &pi) < 0) {
	DBG(0, fprintf(stderr, "unw_get_proc_info failed\n"));
	break;
      }
      #endif
      if (unw_step(&cur) < 0) {
	DBG(1, fprintf(stderr, "unw_step failed\n"));
	break;
      }
    } 
  } while (0);
  if (saved_ui == 0) {
    _UPT_destroy(ui);
  }
  return 0;
}

#if 0
static int get_stack_trace(bulkdbg_conf& cnf, int pid, proc_info& pinfo,
  unsigned int maxlen, const user_regs_struct& regs,
  std::vector<unsigned long>& vals_r)
{
  unsigned long ip = regs.BULKDBG_IP;
  unsigned long fp = regs.BULKDBG_FP;
  DBG(10, fprintf(stderr, "top ip=%lx\n", ip));
  vals_r.push_back(ip);
  unsigned int depth = 0;
  while (fp != 0 && depth < maxlen) {
    unsigned long prevfp = 0;
    unsigned long retaddr = 0;
    prevfp = ptrace(PTRACE_PEEKDATA, pid, fp, 0);
    if (errno != 0) {
      break;
    }
    retaddr = ptrace(PTRACE_PEEKDATA, pid, fp + sizeof(long), 0);
    if (errno != 0) {
      break;
    }
    DBG(10, fprintf(stderr, "ip=%lx fp=%lx\n", retaddr, prevfp));
    if (pinfo.maps.empty()) {
      continue;
    }
    vals_r.push_back(retaddr);
    fp = prevfp;
    ++depth;
  }
  return 0;
}

static int get_stack_trace_sp(bulkdbg_conf& cnf, int pid, proc_info& pinfo,
  unsigned int maxlen, const user_regs_struct& regs,
  std::vector<unsigned long>& vals_r)
{
  unsigned long sp = regs.BULKDBG_SP;
  unsigned long ip = regs.BULKDBG_IP;
  DBG(10, fprintf(stderr, "top ip=%lx\n", ip));
  vals_r.push_back(ip);
  unsigned int i = 0;
  for (i = 0; i < maxlen; ++i) {
    unsigned long retaddr = 0;
    retaddr = ptrace(PTRACE_PEEKDATA, pid, sp + i * sizeof(long), 0);
    if (errno != 0) {
      break;
    }
    if (pinfo.maps.empty()) {
      continue;
    }
    vals_r.push_back(retaddr);
  }
  return 0;
}
#endif

struct bulkdbg {
  bulkdbg();
  ~bulkdbg();
  bulkdbg_conf cnf;
  unw_addr_space_t unw_as;
  proc_info pinfo;
  symbol_table_map stmap;
};

bulkdbg::bulkdbg()
  : unw_as(0)
{
}

bulkdbg::~bulkdbg()
{
  if (unw_as != 0) {
    unw_destroy_addr_space(unw_as);
  }
}

static bool
bulkdbg_prepare_for_backtrace(bulkdbg& bpt)
{
  if (bpt.unw_as != 0) {
    return false;
  }
  bpt.unw_as = unw_create_addr_space(&_UPT_accessors, 0);
  if (!bpt.unw_as) {
    return false;
  }
  if (bpt.cnf.same_map) {
    unw_set_caching_policy(bpt.unw_as, UNW_CACHE_GLOBAL);
  }
  return true;
}

static void
bulkdbg_prepare_maps(bulkdbg& bpt, pid_t pid)
{
  if (!bpt.cnf.same_map || bpt.stmap.empty()) {
    bpt.pinfo = proc_info();
    read_maps(bpt.cnf, pid, bpt.pinfo, bpt.stmap);
  }
}

static bool bulkdbg_backtrace_internal(bulkdbg& bpt, bool attach_flag,
  pid_t pid, std::string& data_r)
{
  bulkdbg_conf& cnf = bpt.cnf;
  bulkdbg_prepare_for_backtrace(bpt);
  bulkdbg_prepare_maps(bpt, pid);
  std::vector<unsigned long> vals;
  std::string edata;
  user_regs_struct regs = { 0 };
  if (attach_flag && ptrace_attach_proc(bpt.cnf, pid) != 0) {
    return false;
  }
  bool r = false;
  do {
    if (get_user_regs(bpt.cnf, pid, regs) != 0) {
      break;
    }
    std::string edata; /* examine data */
    if (get_stack_trace_unw(cnf, bpt.unw_as, 0, pid, bpt.pinfo, 100, regs,
      vals, edata) != 0) {
      break;
    }
    std::string s;
    s = examine_symbols(cnf, bpt.pinfo, regs, vals, vals.size(), edata);
    if (cnf.dump_regs) {
      s = get_user_regs_str(pid, regs) + "\t" + s;
    }
    data_r = s;
    r = true;
  } while (0);
  if (attach_flag) {
    ptrace_detach_proc(bpt.cnf, pid);
  }
  return r;
}

static bool bulkdbg_examine_symbol_internal(bulkdbg& bpt, pid_t pid,
  unsigned long addr, std::string& sym_r, unsigned long& offset_r)
{
  bulkdbg_prepare_maps(bpt, pid);
  const symbol_ent *e = pinfo_find_symbol(bpt.cnf, bpt.pinfo, addr, offset_r);
  if (e != 0) {
    if (bpt.cnf.demangle_cxx) {
      sym_r = cxxdemangle(e->name.c_str());
    } else {
      sym_r = e->name;
    }
    return true;
  }
  return false;
}

static void bulkdbg_pids(bulkdbg& bpt, const std::vector<int>& pids)
{
  typedef std::map<std::string, unsigned> cntmap_type;
  cntmap_type cntmap;
  bulkdbg_conf& cnf = bpt.cnf;
  for (int cnt = 0; cnt < cnf.num_repeat; ++cnt) {
    for (size_t i = 0; i < pids.size(); ++i) {
      pid_t pid = pids[i];
      std::string tr;
      if (!bulkdbg_backtrace_internal(bpt, true, pid, tr)) {
	tr = "[unknown]";
      }
      if (tr.empty()) {
	tr = "[nodata]";
      }
      if (cnf.group_bt == 0) {
	if (cnf.hex_pid) {
	  printf("%x\t%s\n", pid, tr.c_str());
	} else {
	  printf("%d\t%s\n", pid, tr.c_str());
	}
      } else {
	cntmap[tr] += 1;
      }
      #if 0
      if (cnf.dump_sp) {
	dump_stack(cnf, pid, pinfo, regs.BULKDBG_SP, vals_sp, cnf.dump_sp);
      }
      #endif
    }
    if (cnt + 1 < cnf.num_repeat && cnf.repeat_delay != 0) {
      /* delay */
      int denom = RAND_MAX / cnf.repeat_delay;
      int rv = (rand() / denom) * 2;
      struct timespec ts = { 0 };
      #if 0
      fprintf(stderr, "%d\n", rv);
      #endif
      ts.tv_sec = rv / 1000000;
      ts.tv_nsec = (rv % 1000000) * 1000;
      nanosleep(&ts, 0);
    }
  }
  if (cnf.group_bt != 0) {
    for (cntmap_type::const_iterator i = cntmap.begin(); i != cntmap.end();
      ++i) {
      printf("%u\t%s\n", i->second, i->first.c_str());
    }
  }
}

#if 0
static int bulkdbg_pids___(bulkdbg_conf& cnf, const std::vector<int>& pids)
{
  unsigned int trace_length = 0;
  unsigned int unwlength = 0;
  unsigned int fplength = 0;
  unsigned int splength = 0;
  if (cnf.trace_unw) {
    unwlength = cnf.trace_unw;
    trace_length = cnf.trace_unw;
  } else if (cnf.trace_fp) {
    fplength = cnf.trace_fp;
    splength = cnf.dump_sp;
    trace_length = cnf.trace_fp;
  } else {
    fplength = 0;
    splength = std::max(cnf.trace_sp, cnf.dump_sp);
    trace_length = cnf.trace_sp;
  }
  unw_addr_space_t unw_as = 0;
  if (cnf.trace_unw != 0) {
    unw_as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!unw_as) {
      return -1;
    }
    if (cnf.same_map) {
      unw_set_caching_policy(unw_as, UNW_CACHE_GLOBAL);
    }
  }
  int pid = -1;
  proc_info pinfo;
  symbol_table_map stmap;
  typedef std::map<std::string, unsigned> cntmap_type;
  cntmap_type cntmap;
  for (int cnt = 0; cnt < cnf.num_repeat; ++cnt) {
    for (size_t i = 0; i < pids.size(); ++i) {
      pid = pids[i];
      std::vector<unsigned long> vals_fp, vals_sp;
      std::string edata;
      user_regs_struct regs = { 0 };
      if (!cnf.same_map || stmap.empty()) {
	pinfo = proc_info();
	read_maps(cnf, pid, pinfo, stmap);
      }
      bool failed = false;
      if (cnf.procstat) {
	if (get_ipreg_procstat(pid, pinfo, vals_fp) != 0) {
	  failed = true;
	}
      } else {
	if (ptrace_attach_proc(cnf, pid) != 0) {
	  failed = true;
	} else {
	  if (get_user_regs(cnf, pid, regs) != 0) {
	    failed = true;
	  } else {
	    if (unwlength &&
	      get_stack_trace_unw(cnf, unw_as, 0, pid, pinfo, 100, regs,
		vals_fp, edata) != 0) {
	      failed = true;
	    }
	    if (fplength &&
	      get_stack_trace(cnf, pid, pinfo, fplength, regs, vals_fp) != 0) {
	      failed = true;
	    }
	    if (splength &&
	      get_stack_trace_sp(cnf, pid, pinfo, splength, regs, vals_sp)
		!= 0) {
	      failed = true;
	    }
	  }
	}
	ptrace_detach_proc(cnf, pid);
      }
      std::string tr;
      if (!failed) {
	if (cnf.procstat || cnf.trace_unw || cnf.trace_fp) {
	  tr = examine_symbols(cnf, pinfo, regs, vals_fp, trace_length, edata);
	} else {
	  tr = examine_symbols(cnf, pinfo, regs, vals_sp, trace_length, edata);
	}
      } else {
	tr = "[unknown]";
      }
      if (tr.empty()) {
	tr = "[nodata]";
      }
      if (cnf.group_bt == 0) {
	if (cnf.dump_regs) {
	  tr = get_user_regs_str(pid, regs) + "\t" + tr;
	}
	if (cnf.trace_sp != 0 || cnf.trace_fp != 0 || cnf.trace_unw != 0) {
	  if (cnf.hex_pid) {
	    printf("%x\t%s\n", pid, tr.c_str());
	  } else {
	    printf("%d\t%s\n", pid, tr.c_str());
	  }
	}
      } else {
	cntmap[tr] += 1;
      }
      if (cnf.dump_sp) {
	dump_stack(cnf, pid, pinfo, regs.BULKDBG_SP, vals_sp, cnf.dump_sp);
      }
    }
    if (cnt + 1 < cnf.num_repeat && cnf.repeat_delay != 0) {
      /* delay */
      int denom = RAND_MAX / cnf.repeat_delay;
      int rv = (rand() / denom) * 2;
      struct timespec ts = { 0 };
      #if 0
      fprintf(stderr, "%d\n", rv);
      #endif
      ts.tv_sec = rv / 1000000;
      ts.tv_nsec = (rv % 1000000) * 1000;
      nanosleep(&ts, 0);
    }
  }
  if (cnf.group_bt != 0) {
    for (cntmap_type::const_iterator i = cntmap.begin(); i != cntmap.end();
      ++i) {
      printf("%u\t%s\n", i->second, i->first.c_str());
    }
  }
  if (cnf.trace_unw != 0) {
    unw_destroy_addr_space(unw_as);
  }
  return 0;
}
#endif

static void load_syscall_info(bulkdbg_conf& cnf)
{
  #if defined(__i386__)
  const syscall_table_type *p = syscall_table_32;
  #elif defined(__x86_64__)
  const syscall_table_type *p = syscall_table_64;
  #endif
  for (; p->id >= 0; ++p) {
    size_t id = p->id;
    if (cnf.syscall_info_arr.size() <= id) {
      cnf.syscall_info_arr.resize(id + 1);
    }
    syscall_info& e = cnf.syscall_info_arr[id];
    e.name = p->name;
  }
  #ifdef __i386__
  static const syscall_table_type socketcall_table[] = {
    { 1, "socket" },
    { 2, "bind" },
    { 3, "connect" },
    { 4, "listen" },
    { 5, "accept" },
    { 6, "getsockname" },
    { 7, "getpeername" },
    { 8, "socketpair" },
    { 9, "send" },
    { 10, "recv" },
    { 11, "sendto" },
    { 12, "recvfrom" },
    { 13, "shutdown" },
    { 14, "setsockopt" },
    { 15, "getsockopt" },
    { 16, "sendmsg" },
    { 17, "recvmsg" },
    { 18, "accept4" },
    { -1, 0 },
  };
  p = socketcall_table;
  for (; p->id >= 0; ++p) {
    size_t id = p->id;
    if (socketcall_info_arr.size() <= id) {
      socketcall_info_arr.resize(id + 1);
    }
    syscall_info& e = socketcall_info_arr[id];
    e.name = p->name;
  }
  #endif
}

static int strace_proc(bulkdbg_conf& cnf, int pid)
{
  setvbuf(stdout, 0, _IONBF, 0);
  unw_addr_space_t unw_as = 0;
  struct UPT_info *saved_ui = 0;
  if (cnf.trace_unw != 0) {
    unw_as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!unw_as) {
      return -1;
    }
    unw_set_caching_policy(unw_as, UNW_CACHE_GLOBAL);
    saved_ui = (struct UPT_info *)_UPT_create(pid);
  }
  DBG(100, fprintf(stderr, "strace %d\n", pid));
  int err = 0;
  if (ptrace_attach_proc(cnf, pid) != 0) {
    return -1;
  }
  #if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
  if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) != 0) {
    DBG(1, perror("ptrace(PTRACE_SETOPTIONS)"));
    return -1;
  }
  #endif
  int syscall_enter = 1;
  const syscall_info *sinfo_prev = 0;
  std::vector<unsigned long> vals_fp;
  std::string edata;
  proc_info pinfo;
  symbol_table_map stmap;
  pinfo = proc_info();
  read_maps(cnf, pid, pinfo, stmap);
  for (int i = 0; ; ++i, syscall_enter = !syscall_enter) {
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) {
      DBG(1, perror("ptrace(PTRACE_SYSCALL)"));
      err = -1;
      break;
    }
    int st = 0;
    const pid_t v = waitpid(pid, &st, __WALL);
    if (v < 0) {
      DBG(1, perror("waitpid"));
      err = -1;
      break;
    }
    user_regs_struct regs = { 0 };
    if (get_user_regs(cnf, pid, regs) != 0) {
      err = -1;
      break;
    }
    const syscall_info *const sinfo = find_syscall(cnf, regs);
    const char *const syscall_name = sinfo ? sinfo->name : "unknown";
    if (syscall_enter == 0 && sinfo != sinfo_prev) {
      /* possible? */
      DBG(1, fprintf(stderr, "fixed syscal_enter %s %s\n",
        sinfo_prev ? sinfo_prev->name : "unknown", 
        sinfo ? sinfo->name : "unknown"));
      syscall_enter = 1;
    }
    /* i386: ebx, ecx, edx, esi, edi */
    std::string tr;
    if (cnf.trace_unw && syscall_enter != 0) {
      vals_fp.clear();
      edata.clear();
      if (get_stack_trace_unw(cnf, unw_as, saved_ui, pid, pinfo, 100, regs,
	vals_fp, edata) != 0) {
	DBG(1, fprintf(stderr, "failed to get trace unw\n"));
	err = -1;
	break;
      } else {
        tr = examine_symbols(cnf, pinfo, regs, vals_fp, cnf.trace_unw, edata);
      }
    }
    if (syscall_enter) {
      long args[6] = {
	regs.BULKDBG_ARG1,
	regs.BULKDBG_ARG2,
	regs.BULKDBG_ARG3,
	regs.BULKDBG_ARG4,
	regs.BULKDBG_ARG5,
	regs.BULKDBG_ARG6
      };
      printf("%s %s(%lx %lx %lx %lx %lx %lx)", tr.c_str(), syscall_name,
	args[0], args[1], args[2], args[3], args[4], args[5]);
    } else {
      long scret = regs.BULKDBG_A;
      printf(" = %ld\n", scret);
    }
    if (cnf.dump_regs) {
      dump_user_regs(cnf, pid, regs);
    }
    sinfo_prev = sinfo;
    if (cnf.do_strace > 0) {
      if (i >= cnf.do_strace) {
        break;
      }
    }
  }
  ptrace_detach_proc(cnf, pid);
  if (saved_ui != 0) {
    _UPT_destroy(saved_ui);
  }
  return err;
}

static void get_thread_ids(int pid, std::vector<int>& pids_r)
{
  std::vector<int> pids;
  char buf[PATH_MAX];
  snprintf(buf, sizeof(buf), "/proc/%d/task/", pid);
  DIR *dir = opendir(buf);
  if (dir == 0) {
    return;
  }
  while (true) {
    struct dirent *e = readdir(dir);
    if (e == 0) {
      break;
    }
    if (e->d_name[0] == '.') {
      continue;
    }
    pids.push_back(atoi(e->d_name));
  }
  closedir(dir);
  std::sort(pids.begin(), pids.end());
  pids_r.insert(pids_r.end(), pids.begin(), pids.end());
}

static int parse_options(bulkdbg_conf& cnf, int argc, char **argv,
  std::vector<int>& pids_r)
{
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    size_t eq = arg.find('=');
    if (eq != arg.npos) {
      const std::string k = arg.substr(0, eq);
      const std::string v = arg.substr(eq + 1);
      const int vint = atoi(v.c_str());
      if (k == "debug") {
        cnf.debug_level = vint;
      } else if (k == "group") {
        cnf.group_bt = vint;
      } else if (k == "unwtrace") {
        cnf.trace_unw = vint;
        cnf.trace_fp = 0;
        cnf.trace_sp = 0;
      } else if (k == "fptrace") {
        cnf.trace_fp = vint;
        cnf.trace_unw = 0;
        cnf.trace_sp = 0;
	#if defined(__x86_64__)
        cnf.trace_unw = vint;
        cnf.trace_fp = 0;
	#endif
      } else if (k == "procstat") {
	cnf.procstat = vint;
      } else if (k == "sptrace") {
        cnf.trace_sp = vint;
        cnf.trace_fp = 0;
        cnf.trace_unw = 0;
      } else if (k == "showcalls") {
	cnf.show_calls = vint;
      } else if (k == "examine") {
	const std::string s = v;
	std::string::size_type i = s.find(':');
	if (i == s.npos) {
	  fprintf(stderr, "Examine: syntax error: %s\n", s.c_str());
	  return 2;
	}
	std::string fn = s.substr(0, i);
	size_t offset = 0;
	std::string src = s.substr(i + 1);
	std::string upfn;
	i = fn.find(',');
	if (i != fn.npos) {
	  upfn = fn.substr(0, i);
	  fn = fn.substr(i + 1);
	}
	i = fn.find('+');
	if (i != fn.npos) {
	  offset = strtoull(fn.c_str() + i + 1, 0, 0);
	  fn = fn.substr(0, i);
	}
	cnf.exdata_list.push_back(examine_entry());
	examine_entry& ee = cnf.exdata_list.back();
	ee.upfuncname = upfn;
	ee.funcname = fn;
	ee.offset = offset;
	ee.pdata = new peekdata_data();
	peekdata_init(*ee.pdata, src);
	if (!ee.pdata->err.empty()) {
	  fprintf(stderr, "Peekdata: %s\n", ee.pdata->err.c_str());
	  return 2;
	}
	for (std::map<std::string, unsigned long>::const_iterator i
	  = ee.pdata->syms.begin(); i != ee.pdata->syms.end(); ++i) {
	  DBG(10, fprintf(stderr, "Peekdata: sym %s\n", i->first.c_str()));
	  cnf.peekdata_syms[i->first];
	}
      } else if (k == "spdump") {
        cnf.dump_sp = vint;
      } else if (k == "regs") {
        cnf.dump_regs= vint;
      } else if (k == "strace") {
        cnf.do_strace = vint;
      } else if (k == "offset") {
        cnf.show_offset = vint;
	if (v.size() > 0 && v[v.size() - 1] == 'x') {
	  cnf.show_offset_hex = 1;
	}
      } else if (k == "samemap") {
	cnf.same_map = vint;
      } else if (k == "allthreads") {
	cnf.show_threads = vint;
      } else if (k == "demangle") {
	cnf.demangle_cxx = vint;
	if (vint) {
	  cnf.calltrace_delim = ";";
	}
      } else if (k == "hexpid") {
	cnf.hex_pid = vint;
      } else if (k == "showsys") {
	cnf.show_syscall = vint;
      } else if (k == "repeat") {
	cnf.num_repeat = vint;
      } else if (k == "delay") {
	cnf.repeat_delay = vint;
      }
    } else {
      pids_r.push_back(atoi(argv[i]));
    }
  }
  if (cnf.show_threads) {
    if (pids_r.size() > 1) {
      fprintf(stderr, "Can not debug multiple processes when allthreads=1\n");
      return 2;
    } else if (pids_r.size() == 1) {
      int pid = pids_r[0];
      pids_r.clear();
      get_thread_ids(pid, pids_r);
    }
    cnf.same_map = 1;
  }
  return 0;
}

static int bulkdbg_usage(const char *argv0)
{
  fprintf(stderr,
    "Usage: \n"
    "  %s [OPTIONS] PID [PIDS ...]\n", argv0);
  fprintf(stderr,
    "Options: \n"
    "  allthreads=0        - trace all threads\n"
    "  offset=0         - show ip offset for each frame\n"
    "  debug=0          - show debug message\n"
    "  group=0          - group processes/threads by stack trace\n"
    "  regs=0           - show registers\n"
    "  fptrace=100      - number of frames to trace\n"
    #if 0
    "  fptrace=100      - get stack trace using saved frame pointer values\n"
    "  unwtrace=0       - get stack trace using libunwind\n"
    "  sptrace=0        - get stack trace using a heuristic method\n"
    #endif
    "  examine=FUNC:OPS - examine data\n"
    "  showcalls=1      - show call trace\n"
    "  demangle=1       - demangle c++ symbols\n"
    "  hexpid=0         - show process ids in hexadecimal\n"
    "  repeat=1         - \n"
    "  showsys=0        - \n"
    "  delay=0          - \n"
    "  samemap=0        - \n"
    "  spdump=0         - \n"
    "  procstat=0       - \n"
    "  strace=0         - \n");
  return 1;
}

extern "C" {

int bulkdbg_main(int argc, char **argv)
{
  srand(time(0));
  if (argc < 2) {
    return bulkdbg_usage(argv[0]);
  }
  std::vector<int> pids;
  bulkdbg bpt;
  if (parse_options(bpt.cnf, argc, argv, pids) != 0) {
    return 2;
  }
  if (pids.size() == 0) {
    return bulkdbg_usage(argv[0]);
  }
  load_syscall_info(bpt.cnf);
  if (bpt.cnf.do_strace != 0) {
    return strace_proc(bpt.cnf, pids[0]);
  } else {
    bulkdbg_pids(bpt, pids);
    return 0;
  }
}

bulkdbg *bulkdbg_new(const char *confstr)
{
  std::auto_ptr<bulkdbg> bpt(new bulkdbg());
  std::vector<std::string> args;
  if (confstr != 0) {
    std::string s(confstr);
    s += " ";
    size_t p = 0;
    for (size_t i = 0; i < s.size(); ++i) {
      if (s[i] == ' ') {
	if (i != p) {
	  args.push_back(s.substr(p, i - p) + "\0");
	}
	p = i + 1;
      }
    }
  }
  std::vector<char *> argv;
  argv.push_back(0);
  for (size_t i = 0; i < args.size(); ++i) {
    std::string& s = args[i];
    argv.push_back(&s[0]);
  }
  std::vector<int> pids;
  if (parse_options(bpt->cnf, argv.size(), &argv[0], pids) != 0) {
    return 0;
  }
  return bpt.release();
}

void bulkdbg_destroy(bulkdbg *bpt)
{
  delete bpt;
}

char *bulkdbg_backtrace(bulkdbg *bpt, int attach_flag, pid_t pid)
{
  std::string s;
  bool r = bulkdbg_backtrace_internal(*bpt, attach_flag, pid, s);
  if (!r) {
    return 0;
  }
  return strdup(s.c_str());
}

char *bulkdbg_examine_symbol(bulkdbg *bpt, pid_t pid, unsigned long addr,
  unsigned long *offset_r)
{
  std::string s;
  unsigned long o = 0;
  bool r = bulkdbg_examine_symbol_internal(*bpt, pid, addr, s, o);
  if (!r) {
    return 0;
  }
  if (offset_r != 0) {
    *offset_r = o;
  }
  return strdup(s.c_str());
}

};


