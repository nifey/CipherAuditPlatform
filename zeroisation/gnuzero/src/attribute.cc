#include <memory>
#include <string>

#include <gcc-plugin.h>
#include <stringpool.h>
#include <tree.h>
#include <print-tree.h>
#include <attribs.h>
#include <diagnostic.h>
#include <analyzer/analyzer.h>
#include <analyzer/analyzer-logging.h>

#include "plugin-init.h"
#include "sm_scrub.h"

using namespace ana;

tree
empty_attribute_handler (tree *node, tree name, tree args, int flags,
                         bool *no_add_attrs)
{
  return NULL_TREE;
}

tree
scrubber_attr_handler (tree *node, tree name, tree args, int flags,
                       bool *no_add_attrs)
{
  tree inner = *node;
  if (TREE_CODE (TREE_TYPE (inner)) == FUNCTION_TYPE)
    if (TREE_CODE (inner) == FUNCTION_DECL)
      if (tree fn_name = DECL_NAME (inner))
        if (const char *name_ptr = IDENTIFIER_POINTER (fn_name))
          {
            if (DEBUG)
              inform (input_location,
                      "Found attribute %qE on"
                      " function %qE",
                      name, inner);
            ana::scrubbers.safe_push (name_ptr);
          }
  return NULL_TREE;
}