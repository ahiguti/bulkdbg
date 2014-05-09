
#ifndef BULKDBG_HPP
#define BULKDBG_HPP

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bulkdbg;

int bulkdbg_main(int argc, char **argv);
struct bulkdbg *bulkdbg_new(const char *confstr);
void bulkdbg_destroy(struct bulkdbg *bpt);
char *bulkdbg_backtrace(struct bulkdbg *bpt, int attach_flag, pid_t pid);
char *bulkdbg_examine_symbol(struct bulkdbg *bpt, pid_t pid,
  unsigned long addr, unsigned long *offset_r);

#ifdef __cplusplus
};
#endif

#endif

