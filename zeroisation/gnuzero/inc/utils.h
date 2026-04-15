#ifndef __UTILS_H
#define __UTILS_H

#include <gcc-plugin.h>
#include <analyzer/analyzer-logging.h>

tree reduce_tree (tree, ana::logger *);

/*
  This function takes a DECL as parameter and returns it if it has the SCRUB
  attribute */
bool should_be_scrubbed (tree, ana::logger *, bool = true);

#endif //__UTILS_H