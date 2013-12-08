
// vim: ai sw=2

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <limits.h>
#include <string.h>
#include <sched.h>
#include <list>
#include <vector>
#include <map>
#include <string>
#include <memory>
#include <bfd.h>
#include <algorithm>
#include <libelf.h>

#include <linux/version.h>
#include <asm/unistd.h>

#include <libunwind-ptrace.h>

#include "syscall_table.hpp"

#define DBG(v, x) if (debug_level >= v) { x; }

#if defined(__i386__)
#define BULKDBG_IP eip
#define BULKDBG_SP esp
#define BULKDBG_FP ebp
#define BULKDBG_ORIG_A orig_eax
#elif defined(__x86_64__)
#define BULKDBG_IP rip
#define BULKDBG_SP rsp
#define BULKDBG_FP rbp
#define BULKDBG_ORIG_A orig_rax
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

static int debug_level = 0;
static int group_bt = 0;
static int trace_unw = 100;
static int trace_fp = 0;
static int trace_sp = 0;
static int dump_sp = 0;
static int dump_regs = 0;
static int do_strace = 0;
static int show_offset = 0;
static syscall_info_arr_type syscall_info_arr;
static syscall_info_arr_type socketcall_info_arr;

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
  symbol_table() : text_vma(0), text_size(0) { }
};

static int load_symbol_table(const char *filename, symbol_table& st)
{
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
    if ((sym->flags & BSF_FUNCTION) == 0) {
      continue;
    }
    symbol_info sinfo;
    bfd_get_symbol_info(abfd.get(), sym, &sinfo);
    if (sinfo.type != 'T' && sinfo.type != 't' && sinfo.type != 'W' &&
      sinfo.type != 'w') {
      continue;
    }
    DBG(10, fprintf(stderr, "%s %lx f=%x\n", sinfo.name, (long)sinfo.value,
      (int)sym->flags));
    symbol_ent e;
    e.addr = sinfo.value;
    e.name = std::string(sinfo.name);
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
  symbol_table *get(const std::string& path) {
    m_type::iterator i = m.find(path);
    if (i != m.end()) {
      return i->second;
    }
    std::auto_ptr<symbol_table> p(new symbol_table);
    if (load_symbol_table(path.c_str(), *p) != 0 || p->symbols.empty()) {
      p.reset();
    }
    m[path] = p.get(); /* can be 0 */
    return p.release();
  }
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

static int ptrace_attach_proc(int pid)
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

static int ptrace_detach_proc(int pid)
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
  operator unsigned long() const { return addr_begin; } /* for comparison */
  proc_map_ent() : addr_begin(0), addr_size(0), offset(0), stbl(0),
    relative(false), is_vdso(false) { }
};

struct proc_info {
  typedef std::vector<proc_map_ent> maps_type;
  maps_type maps;
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
  bool found = false;
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
      found = true;
      break;
    }
  }
  elf_end(elf);
  return vaddr == 0;
}

static void read_proc_map_ent(char *line, proc_info& pinfo,
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
    e.stbl = stmap.get(e.path);
  }
  if (e.stbl != 0) {
    /* wrong? */
    e.relative = check_shlib(e.path);
    DBG(10, fprintf(stderr, "%s: relative=%d addr_begin=%lx\n", e.path.c_str(),
      (int)e.relative, e.addr_begin));
  }
  pinfo.maps.push_back(e);
}

static void read_maps(int pid, proc_info& pi, symbol_table_map& stmap)
{
  char fn[PATH_MAX];
  char buf[4096];
  snprintf(fn, sizeof(fn), "/proc/%d/maps", pid);
  auto_fp fp(fopen(fn, "r"));
  if (fp == 0) {
    return;
  }
  while (fgets(buf, sizeof(buf), fp) != 0) {
    read_proc_map_ent(buf, pi, stmap);
  }
  std::sort(pi.maps.begin(), pi.maps.end(), std::less<unsigned long>());
    /* already sorted? */
}

static int get_stack_trace_unw(unw_addr_space_t unw_as, int pid,
  proc_info& pinfo, unsigned int maxlen, const user_regs_struct& regs,
  std::vector<unsigned long>& vals_r)
{
  struct UPT_info *ui = (struct UPT_info *)_UPT_create(pid);
  unw_cursor_t cur;
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
      DBG(10, fprintf(stderr, "ip=%lx\n", ip));
      if (ip_prev == ip) {
	break;
      }
      ip_prev = ip;
      vals_r.push_back(ip);
      if (unw_get_reg(&cur, UNW_REG_SP, &sp) < 0) {
	DBG(0, fprintf(stderr, "unw_get_reg sp failed\n"));
	break;
      }
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
	DBG(0, fprintf(stderr, "unw_step failed\n"));
	break;
      }
    } 
  } while (0);
  _UPT_destroy(ui);
  return 0;
}

static int get_stack_trace(int pid, proc_info& pinfo, unsigned int maxlen,
  const user_regs_struct& regs, std::vector<unsigned long>& vals_r)
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

static int get_stack_trace_sp(int pid, proc_info& pinfo, unsigned int maxlen,
  const user_regs_struct& regs, std::vector<unsigned long>& vals_r)
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

static int get_user_regs(int pid, user_regs_struct& regs)
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

static const symbol_ent *pinfo_find_symbol(const proc_info& pinfo,
  unsigned long addr, unsigned long& offset_r)
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
    if (i->is_vdso) {
      offset_r = addr - i->addr_begin;
    }
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
    }
  }
  return 0;
}

const syscall_info *find_syscall(const user_regs_struct& regs)
{
  const int syscall_num = regs.BULKDBG_ORIG_A;
  const syscall_info *sinfo = 0;
  if (syscall_num >= 0 && (size_t)syscall_num < syscall_info_arr.size()) {
    sinfo = &syscall_info_arr[syscall_num];
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

static std::string examine_stack_trace(const proc_info& pinfo,
   const user_regs_struct& regs, const std::vector<unsigned long>& vals,
   size_t maxlen)
{
  std::string rstr;
  /* vals[0] is ip */
  for (size_t i = 0; i < std::min(vals.size(), maxlen); ++i) {
    unsigned long addr = vals[i];
    unsigned long offset = 0;
    const symbol_ent *e = pinfo_find_symbol(pinfo, addr, offset);
    if (e != 0) {
      const syscall_info *sinfo = 0;
      if (i == 0 && e->name == "_dl_sysinfo_int80" && offset == 2) { // TODO
        sinfo = find_syscall(regs);
      }
      if (offset != 0) {
	if (!rstr.empty()) {
	  rstr += ":";
	}
	if (sinfo != 0) {
	  rstr += std::string(sinfo->name);
	} else {
	  rstr += e->name;
	}
	if (show_offset) {
	  char buf[32];
	  snprintf(buf, 32, "(%lx)", offset);
	  rstr += std::string(buf);
	}
      }
    } else if (offset != 0) {
      /* vdso */
      if (i == 0 && offset == 0x410) { // TODO: correct?
        const syscall_info *sinfo = find_syscall(regs);
	if (sinfo != 0) {
	  rstr += std::string(sinfo->name);
	}
      }
    }
  }
  return rstr;
}

static void dump_stack(int pid, const proc_info& pinfo, unsigned long sp,
  const std::vector<unsigned long>& vals, size_t maxlen)
{
  for (size_t i = 1; i < std::min(vals.size(), maxlen + 1);
    ++i, sp += sizeof(long)) {
    unsigned long val = vals[i];
    std::string sym;
    unsigned long offset = 0;
    const symbol_ent *e = pinfo_find_symbol(pinfo, val, offset);
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

static void dump_user_regs(int pid, const user_regs_struct& regs)
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
  printf("%d r %s\n", pid, s.c_str());
}

static int bulkdbg_pids(const std::vector<int>& pids)
{
  unsigned int trace_length = 0;
  unsigned int unwlength = 0;
  unsigned int fplength = 0;
  unsigned int splength = 0;
  if (trace_unw) {
    unwlength = trace_unw;
    trace_length = trace_unw;
  } else if (trace_fp) {
    fplength = trace_fp;
    splength = dump_sp;
    trace_length = trace_fp;
  } else {
    fplength = 0;
    splength = std::max(trace_sp, dump_sp);
    trace_length = trace_sp;
  }
  unw_addr_space_t unw_as = 0;
  if (trace_unw != 0) {
    unw_as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!unw_as) {
      return -1;
    }
  }
  symbol_table_map stmap;
  typedef std::map<std::string, unsigned> cntmap_type;
  cntmap_type cntmap;
  for (size_t i = 0; i < pids.size(); ++i) {
    const int pid = pids[i];
    proc_info pinfo;
    std::vector<unsigned long> vals_fp, vals_sp;
    user_regs_struct regs = { 0 };
    read_maps(pid, pinfo, stmap);
    bool failed = false;
    if (ptrace_attach_proc(pid) != 0) {
      failed = true;
    } else {
      if (get_user_regs(pid, regs) != 0) {
        failed = true;
      } else {
	if (unwlength &&
	  get_stack_trace_unw(unw_as, pid, pinfo, 100, regs, vals_fp) != 0) {
	  failed = true;
	};
	if (fplength &&
	  get_stack_trace(pid, pinfo, fplength, regs, vals_fp) != 0) {
	  failed = true;
	}
	if (splength &&
	  get_stack_trace_sp(pid, pinfo, splength, regs, vals_sp) != 0) {
	  failed = true;
	}
      }
    }
    ptrace_detach_proc(pid);
    std::string tr;
    if (!failed) {
      if (trace_unw || trace_fp) {
        tr = examine_stack_trace(pinfo, regs, vals_fp, trace_length);
      } else {
        tr = examine_stack_trace(pinfo, regs, vals_sp, trace_length);
      }
    } else {
      tr = "[unknown]";
    }
    if (tr.empty()) {
      tr = "[notfound]";
    }
    if (group_bt == 0) {
      if (trace_sp != 0 || trace_fp != 0 || trace_unw != 0) {
        printf("%d\t%s\n", pid, tr.c_str());
      }
      if (dump_regs) {
        dump_user_regs(pid, regs);
      }
    } else {
      cntmap[tr] += 1;
    }
    if (dump_sp) {
      dump_stack(pid, pinfo, regs.BULKDBG_SP, vals_sp, dump_sp);
    }
  }
  if (group_bt != 0) {
    for (cntmap_type::const_iterator i = cntmap.begin(); i != cntmap.end();
      ++i) {
      printf("%u\t%s\n", i->second, i->first.c_str());
    }
  }
  if (trace_unw != 0) {
    unw_destroy_addr_space(unw_as);
  }
  return 0;
}

static void load_syscall_info()
{
  #if defined(__i386__)
  const syscall_table_type *p = syscall_table_32;
  #elif defined(__x86_64__)
  const syscall_table_type *p = syscall_table_64;
  #endif
  for (; p->id >= 0; ++p) {
    size_t id = p->id;
    if (syscall_info_arr.size() <= id) {
      syscall_info_arr.resize(id + 1);
    }
    syscall_info& e = syscall_info_arr[id];
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

static int strace_proc(int pid)
{
  DBG(100, fprintf(stderr, "strace %d\n", pid));
  int err = 0;
  if (ptrace_attach_proc(pid) != 0) {
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
    if (get_user_regs(pid, regs) != 0) {
      err = -1;
      break;
    }
    const syscall_info *const sinfo = find_syscall(regs);
    const char *const syscall_name = sinfo ? sinfo->name : "unknown";
    if (syscall_enter == 0 && sinfo != sinfo_prev) {
      /* possible? */
      DBG(1, fprintf(stderr, "fixed syscal_enter %s %s\n",
        sinfo_prev ? sinfo_prev->name : "unknown", 
        sinfo ? sinfo->name : "unknown"));
      syscall_enter = 1;
    }
    /* i386: ebx, ecx, edx, esi, edi */
    printf("enter = %d syscall=%s\n", syscall_enter, syscall_name);
    if (dump_regs) {
      dump_user_regs(pid, regs);
    }
    sinfo_prev = sinfo;
    if (do_strace > 0) {
      if (i >= do_strace) {
        break;
      }
    }
  }
  ptrace_detach_proc(pid);
  return err;
}

static void parse_options(int argc, char **argv, std::vector<int>& pids_r)
{
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    size_t eq = arg.find('=');
    if (eq != arg.npos) {
      const std::string k = arg.substr(0, eq);
      const std::string v = arg.substr(eq + 1);
      const int vint = atoi(v.c_str());
      if (k == "debug") {
        debug_level = vint;
      } else if (k == "group") {
        group_bt = vint;
      } else if (k == "unwtrace" || k == "fptrace") {
        trace_unw = vint;
        trace_fp = 0;
        trace_sp = 0;
      #if 0
      } else if (k == "fptrace") {
        trace_fp = vint;
        trace_unw = 0;
        trace_sp = 0;
      #endif
      } else if (k == "sptrace") {
        trace_sp = vint;
        trace_fp = 0;
        trace_unw = 0;
      } else if (k == "spdump") {
        dump_sp = vint;
      } else if (k == "regs") {
        dump_regs= vint;
      } else if (k == "strace") {
        do_strace = vint;
      } else if (k == "offset") {
        show_offset = vint;
      }
    } else {
      pids_r.push_back(atoi(argv[i]));
    }
  }
}

static int usage(const char *argv0)
{
  fprintf(stderr,
    "Usage: \n"
    "  %s [OPTIONS] PROCESS_OR_THREAD_ID [...]\n", argv0);
  fprintf(stderr,
    "Options: \n"
    "  fptrace=100      - show stack trace for each process/thread\n"
    "  offset=0         - show ip offset for each frame\n"
    "  debug=0          - show debug message\n"
    "  group=0          - group processes/threads by stack trace\n"
    "  regs=0           - show registers\n"
    #if 0
    "  unwtrace=0       - ???\n"
    "  fptrace=0        - ???\n"
    #endif
    "  sptrace=0        - ???\n"
    "  spdump=0         - ???\n"
    "  strace=0         - ???\n");
  return 1;
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    return usage(argv[0]);
  }
  std::vector<int> pids;
  parse_options(argc, argv, pids);
  if (pids.size() == 0) {
    return 0;
  }
  load_syscall_info();
  if (do_strace != 0) {
    return strace_proc(pids[0]);
  } else {
    return bulkdbg_pids(pids);
  }
}
