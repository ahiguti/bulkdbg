
#ifndef BULKDBG_SYSCALL_TABLE_HPP
#define BULKDBG_SYSCALL_TABLE_HPP

struct syscall_table_type {
  int id;
  const char *name;
};

extern const syscall_table_type syscall_table_32[];
extern const syscall_table_type syscall_table_64[];

#endif

