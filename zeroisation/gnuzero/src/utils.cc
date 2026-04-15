#include <gcc-plugin.h>
#include <stringpool.h>
#include <tree.h>
#include <print-tree.h>
#include <attribs.h>
#include <analyzer/analyzer-logging.h>

#include "plugin-init.h"
#include "sm_scrub.h"

using namespace ana;

/* This function tries to reduce a given tree to either a VAR_DECL or a
 *  PARM_DECL
 */
/* TODO: add an integer for a max depth */
tree
reduce_tree (tree t, logger *logger)
{
  LOG_SCOPE (logger);

  tree res = t;
  while (res && TREE_CODE (res) != VAR_DECL && TREE_CODE (res) != PARM_DECL)
    {
      if (TREE_CODE (res) == SSA_NAME)
        {
          /* For temporary variable (i.e., '_1'), will return NULL_TREE */
          if (SSA_NAME_VAR (res))
            res = SSA_NAME_VAR (res);
          else
            break;
        }
      else if (TREE_CODE (res) == COMPONENT_REF || TREE_CODE (res) == MEM_REF
               || TREE_CODE (res) == ARRAY_REF || TREE_CODE (res) == ADDR_EXPR)
        res = TREE_OPERAND (res, 0);
      else
        break;
    }

  if (DEBUG && logger)
    {
      logger->start_log_line ();
      logger->log_partial ("input :");
      logger->end_log_line ();
      print_node (logger->get_file (), "", t, 0);
      logger->end_log_line ();
      if (res && res != t)
        {
          logger->start_log_line ();
          logger->log_partial ("res :");
          logger->end_log_line ();
          print_node (logger->get_file (), "", res, 0);
          logger->end_log_line ();
        }
    }

  return res;
}

bool
should_be_scrubbed (tree t, logger *logger, bool reduce)
{
  LOG_SCOPE (logger);
  if (reduce)
    {
      t = reduce_tree (t, logger);
    }
  if (to_scrub.contains (t))
    return true;
  else if (t && DECL_P (t)
           && lookup_attribute (TO_SCRUB_STR, DECL_ATTRIBUTES (t)))
    {
      to_scrub.safe_push (t);
      if (DEBUG)
        {
          auto ctx
              = DECL_CONTEXT (t) ? ::get_name (DECL_CONTEXT (t)) : "<no_ctx>";
          inform (input_location,
                  "Found attribute %qs on %qE in context of"
                  " function %qs",
                  TO_SCRUB_STR, t, ctx);
        }
      return true;
    }
  else
    return false;
}