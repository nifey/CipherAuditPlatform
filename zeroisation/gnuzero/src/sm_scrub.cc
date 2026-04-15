#include <memory>
#include <string>

#include <gcc-plugin.h>
#include <tree.h>
#include <gimple.h>
#include <gimple-pretty-print.h>
#include <diagnostic.h>
#include <diagnostic-metadata.h>
#include <cgraph.h>
#include <analyzer/analyzer.h>
#include <analyzer/analyzer-logging.h>
#include <analyzer/sm.h>
#include <analyzer/store.h>
#include <analyzer/program-state.h>
#include <analyzer/region-model.h>
#include <analyzer/call-details.h>
#include <analyzer/supergraph.h>
#include <analyzer/inlining-iterator.h>
#include <analyzer/checker-event.h>

#include "attribute.h"
#include "plugin-init.h"
#include "utils.h"

using namespace std;

static const string SM_NAME ("scrub");
static const string MALLOC ("malloc");
static const string ALLOCA ("alloca");
static const string MEMSET ("memset");
static const string FREE ("free");
static const string REALLOC ("realloc");
static const string MEMCPY ("memcpy");

namespace ana
{

class scrubber
{
public:
  scrubber (const char *name) : m_name (name) {}
  const char *
  get_name () const
  {
    return m_name;
  }
  bool
  operator== (const scrubber &other) const
  {
    return m_name == other.get_name ()
           || strcmp (m_name, other.get_name ()) == 0;
  }

private:
  DISABLE_COPY_AND_ASSIGN (scrubber);

  const char *m_name;
};

// auto_vec<tree> scrubbers;
auto_vec<scrubber> scrubbers;
auto_vec<tree> to_scrub;

void
dump_scrubber (logger *logger)
{
  if (logger)
    {
      unsigned idx;
      scrubber *elm;
      logger->start_log_line ();
      logger->log_partial ("scrubbers: {");
      FOR_EACH_VEC_ELT (scrubbers, idx, elm)
      {
        if (idx == 0)
          logger->log_partial (" %d: %qs", idx, elm->get_name ());
        else
          logger->log_partial (", %d: %qs", idx, elm->get_name ());
      }
      logger->log_partial (" }");
      logger->end_log_line ();
    }
}

namespace
{

/* Enum class used to differentiate between known function calls.
 *  Ideally, this
 *  would be implemented as ana::known_function, but this would overwrite some
 *  of the SA behavior for now.
 */

enum class call_kind
{
  Malloc,
  Alloca,
  Realloc,
  Free,
  Memset,
  Memcpy,
  None
};

call_kind
build_call_kind (const char *ptr)
{
  auto name = ptr;
  // Move pointer if currently checking for a builtin function (e.g.,
  // '__builtin_alloca')
  if (strncmp ("__builtin_", name, 10) == 0)
    name += 10;

  if (MALLOC == name)
    return call_kind::Malloc;
  else if (ALLOCA == name)
    return call_kind::Alloca;
  else if (FREE == name)
    return call_kind::Free;
  else if (REALLOC == name)
    return call_kind::Realloc;
  else if (MEMSET == name)
    return call_kind::Memset;
  else if (MEMCPY == name)
    return call_kind::Memcpy;
  else
    return call_kind::None;
}

/* Custom state to differentiate between the resource_kind */

class scrub_state : public state_machine::state
{
public:
  /* Enum class to differentiate between the kind of resources. */
  enum class resource_kind
  {
    RS_START,
    RS_HEAP,
    RS_STACK,
  };

  scrub_state (const char *name, unsigned id, resource_kind rk)
      : state (name, id), m_kind (rk)
  {
  }

  void
  dump_to_pp (pretty_printer *pp) const override
  {
    state_machine::state::dump_to_pp (pp);
    pp_string (pp, " (");
    dump_rk (pp, m_kind);
    pp_character (pp, ')');
  }

  static inline void
  dump_rk (pretty_printer *pp, scrub_state::resource_kind rk)
  {
    switch (rk)
      {
      case resource_kind::RS_HEAP:
        pp_printf (pp, "%s", "heap");
        break;
      case resource_kind::RS_STACK:
        pp_printf (pp, "%s", "stack");
        break;
      case resource_kind::RS_START:
      default:
        break;
      }
  }

  const resource_kind m_kind;
};

typedef const scrub_state *scrub_state_t;
typedef scrub_state::resource_kind resource_kind;

/* Return STATE cast to the custom state subclass, or NULL for the start state.
   Everything should be an allocation_state apart from the start state.  */
static inline scrub_state_t
dyn_cast_scrub_state (state_machine::state_t state)
{
  if (state->get_id () == 0 || state->get_id () == 1)
    return NULL;
  return static_cast<scrub_state_t> (state);
}

/* Get the resource_kind for STATE.  */
static inline resource_kind
get_rk (state_machine::state_t state)
{
  if (const scrub_state_t astate = dyn_cast_scrub_state (state))
    return astate->m_kind;
  else
    return resource_kind::RS_START;
}

/* Return true if STATE is heap allocated. */
static inline bool
heap_unscrubbed_p (state_machine::state_t state)
{
  return get_rk (state) == resource_kind::RS_HEAP;
}

/* Return true if STATE is stack allocated. */
static inline bool
stack_unscrubbed_p (state_machine::state_t state)
{
  return get_rk (state) == resource_kind::RS_STACK;
}

/* Return true if STATE is not a parameter but is either heap or stack
 * allocated.
 */
static inline bool
unscrubbed_p (state_machine::state_t state)
{
  return heap_unscrubbed_p (state) || stack_unscrubbed_p (state);
}

/* Return true if REG is on heap. */

static inline bool
heap_memory_space_p (const region *reg, sm_context *sm_ctx)
{
  bool is_heap_allocated_decl = false;
  if (const decl_region *decl_reg = reg->dyn_cast_decl_region ())
    if (tree decl = decl_reg->maybe_get_decl ())
      if (any_pointer_p (decl))
        {
          auto model = sm_ctx->get_old_region_model ();
          if (const svalue *ptr = model->get_rvalue (decl, nullptr))
            if (const region *deref_reg
                = model->deref_rvalue (ptr, decl, nullptr))
              is_heap_allocated_decl
                  = deref_reg->get_kind () == RK_HEAP_ALLOCATED;
        }
  return reg->get_memory_space () == MEMSPACE_HEAP || is_heap_allocated_decl;
}

/* Return true if REG is on stack.
 *  WARNING: it can be either a local or a parameter.
 */

static inline bool
stack_memory_space_p (const region *reg)
{
  return reg->get_memory_space () == MEMSPACE_STACK;
}

/* Return true if REG is either on stack or on heap. */
// static bool
// heap_or_stack_memory_space_p (const region *reg)
// {
//   return heap_memory_space_p (reg) || stack_memory_space_p (reg);
// }

/* Return true if T is not an anonym SSA, e.g., "x_1" */
static inline bool
named_ssa_p (tree t)
{
  return TREE_CODE (t) == SSA_NAME && SSA_NAME_VAR (t)
         && TREE_CODE (SSA_NAME_VAR (t)) == VAR_DECL;
}

/* Return true if T is an anonym SSA, e.g., "_1" */
static inline bool
anonym_ssa_p (tree t)
{
  return TREE_CODE (t) == SSA_NAME && !SSA_NAME_VAR (t);
}

/* Return true if T is a VAR_DECL. */
static inline bool
var_decl_p (tree t)
{
  if (t)
    return TREE_CODE (t) == VAR_DECL;
  return false;
}

/* Return true if T is a PARM_DECL. */
static inline bool
parm_decl_p (tree t)
{
  if (t)
    return TREE_CODE (t) == PARM_DECL;
  return false;
}

static inline void
dump_state (logger *logger, state_machine::state_t state)
{
  if (logger)
    {
      logger->log_partial (" | state: %s", state->get_name ());
      if (state->get_id () != 0)
        {
          auto pp = logger->get_printer ();
          pp_left_paren (pp);
          scrub_state::dump_rk (pp, get_rk (state));
          pp_right_paren (pp);
        }
    }
}

static inline void
debug_state (logger *logger, state_machine::state_t state)
{
  if (logger)
    {
      logger->start_log_line ();
      logger->log_partial ("state: %s", state->get_name ());
      if (state->get_id () != 0)
        {
          auto pp = logger->get_printer ();
          pp_left_paren (pp);
          scrub_state::dump_rk (pp, get_rk (state));
          pp_right_paren (pp);
        }
      logger->end_log_line ();
    }
}

static inline void
log_rhs (logger *logger, unsigned idx, tree t, const region *reg,
         state_machine::state_t state, tree reduced = NULL_TREE)
{
  if (logger)
    {
      auto pp = logger->get_printer ();
      logger->start_log_line ();
      logger->log_partial ("rhs%d: tree: ", idx);
      t ? dump_quoted_tree (pp, t) : logger->log_partial ("NULL_TREE");
      if (reduced)
        {
          logger->log_partial (" | reduced: ");
          dump_quoted_tree (pp, reduced);
        }
      if (reg)
        {
          logger->log_partial (" | region: ");
          reg->dump_to_pp (pp, SIMPLE);
        }
      logger->log_partial (" | considered_rhs: ");
      named_ssa_p (t) && reduced ? dump_quoted_tree (pp, reduced)
                                 : dump_quoted_tree (pp, t);
      dump_state (logger, state);
      logger->end_log_line ();
    }
}

static inline void
dump_state_change (logger *logger, const evdesc::state_change &change)
{
  /* tree m_expr;
   * tree m_origin;
   * state_machine::state_t m_old_state;
   * state_machine::state_t m_new_state;
   * diagnostic_event_id_t m_event_id;
   * const state_change_event &m_event;
   */
  if (logger)
    {
      auto pp = logger->get_printer ();
      logger->start_log_line ();
      logger->log_partial ("state_change: {m_expr: ");
      change.m_expr ? dump_quoted_tree (pp, change.m_expr)
                    : logger->log_partial ("NULL_TREE");
      logger->log_partial (", m_origin: ");
      change.m_origin ? dump_quoted_tree (pp, change.m_origin)
                      : logger->log_partial ("NULL_TREE");
      logger->log_partial (", m_old_state: ");
      dump_state (logger, change.m_old_state);
      logger->log_partial (", m_new_state: ");
      dump_state (logger, change.m_new_state);
      pp_right_brace (pp);
      logger->end_log_line ();
    }
}

static inline void
dump_final_state (logger *logger, const evdesc::final_event &ev)
{
  /* tree m_expr;
   * state_machine::state_t m_state;
   */
  if (logger)
    {
      auto pp = logger->get_printer ();
      logger->start_log_line ();
      logger->log_partial ("final_event: {m_expr: ");
      ev.m_expr ? dump_quoted_tree (pp, ev.m_expr)
                : logger->log_partial ("NULL_TREE");
      logger->log_partial (", m_state: ");
      dump_state (logger, ev.m_state);
      pp_right_brace (pp);
      logger->end_log_line ();
    }
}

class sm_scrub : public state_machine
{
public:
  sm_scrub (logger *);
  virtual bool inherited_state_p () const override final;
  virtual state_t
  alt_get_inherited_state (const sm_state_map &, const svalue *,
                           const extrinsic_state &) const override final;
  virtual state_t
  alt_get_inherited_state (const sm_state_map &, const region *,
                           const extrinsic_state &) const override final;
  virtual bool on_stmt (sm_context *, const supernode *,
                        const gimple *) const override final;
  virtual bool can_purge_p (state_t) const override final;
  virtual void on_phi (sm_context *, const supernode *, const gphi *,
                       tree) const override final;
  virtual void on_push_frame (sm_context *, const supernode *,
                              const frame_region *,
                              const gimple *) const final override;
  virtual void on_pop_frame (sm_state_map *, const frame_region *, tree,
                             const gimple *, sm_context *,
                             const supernode *) const override final;
  virtual std::unique_ptr<pending_diagnostic>
  on_leak (tree, const svalue *, const sm_context *) const override final;
  virtual void
  on_realloc_with_move (region_model *, sm_state_map *, const svalue *,
                        const svalue *, const extrinsic_state &, sm_context *,
                        const call_details &) const override final;

  virtual bool
  reset_when_passed_to_unknown_fn_p (
      state_t state UNUSED, bool is_mutable UNUSED) const override final
  {
    LOG_SCOPE (get_logger ());
    return state != m_heap && state != m_stack;
  }

  inline state_t
  get_stack_state () const
  {
    return m_stack;
  }

  inline state_t
  get_heap_state () const
  {
    return m_heap;
  }

  inline state_t
  get_param_state () const
  {
    return m_param;
  }

  inline state_t
  get_scrubbed_state () const
  {
    return m_scrubbed;
  }

private:
  const char *get_fn_identifier (sm_context *, const gcall *) const;
  void on_allocator (sm_context *, const supernode *, const gcall *,
                     const resource_kind) const;
  void on_realloc (sm_context *, const supernode *, const gcall *) const;
  void on_free (sm_context *, const supernode *, const gcall *) const;
  void on_memset (sm_context *, const supernode *, const gcall *) const;
  void on_memcpy (sm_context *, const supernode *, const gcall *) const;
  bool on_call (sm_context *, const supernode *, const gcall *) const;
  void on_scrubber (sm_context *, const supernode *, call_details &,
                    const char *) const;
  bool on_known_fn_call (sm_context *, const supernode *, const gcall *,
                         const call_kind) const;
  void handle_assign_stmt (sm_context *, const supernode *,
                           const gassign *) const;
  void propagate (sm_context *, const supernode *, const gassign *, tree,
                  tree) const;
  bool is_scrubbing_assignment (sm_context *, const gassign *) const;
  void on_scrubbing_assignment (sm_context *, const supernode *,
                                const gassign *, tree, tree) const;
  tristate is_null (const sm_context *, const svalue *) const;
  tree inside_inlined_scrubber_fn (sm_context *, const gimple *) const;
  state_t get_corresponding_state (const region *, tree, sm_context *) const;

  state_t
  add_state (const char *name, enum scrub_state::resource_kind rk)
  {
    return add_custom_state (new scrub_state (name, alloc_state_id (), rk));
  }

  inline bool
  maybe_scrub (tree lhs, tree reduced_lhs) const
  {
    if (!reduced_lhs)
      reduced_lhs = reduce_tree (lhs, nullptr);
    return should_be_scrubbed (reduced_lhs, nullptr, false)
           || TREE_CODE (reduced_lhs) == PARM_DECL;
  }

  inline bool
  check_state (sm_context *sm_ctx, const gimple *stmt, const tree var,
               const state_t s) const
  {
    return sm_ctx->get_state (stmt, var, !any_pointer_p (var)) == s;
  }

  inline bool
  check_state (sm_context *sm_ctx, const gimple *stmt, const svalue *sval,
               const state_t s) const
  {
    return sm_ctx->get_state (stmt, sval) == s;
  }

  inline bool
  check_state (sm_context *sm_ctx, const gimple *stmt, const region *reg,
               const state_t s) const
  {
    return sm_ctx->get_state (stmt, reg) == s;
  }

  state_t m_scrubbed;
  state_t m_stack;
  state_t m_heap;
  state_t m_param;
};

class scrub_diagnostic : public pending_diagnostic
{
public:
  scrub_diagnostic (const sm_scrub &sm, tree arg) : m_sm (sm), m_arg (arg) {}

  bool
  subclass_equal_p (const pending_diagnostic &base_other) const override
  {
    return same_tree_p (m_arg, ((const scrub_diagnostic &)base_other).m_arg);
  }

protected:
  const sm_scrub &m_sm;
  tree m_arg;
};

class data_leak : public scrub_diagnostic
{
public:
  data_leak (const sm_scrub &sm, tree arg, int cwe, bool known = true)
      : scrub_diagnostic (sm, arg), m_cwe (cwe), m_known (known)
  {
  }

  const char *
  get_kind () const override
  {
    return "data_leak";
  }

  int
  get_controlling_option () const final override
  {
    return OPT_Wanalyzer_malloc_leak;
  }

  bool
  emit (rich_location *rich_loc) final override
  {
    diagnostic_metadata m;
    m.add_cwe (m_cwe);
    const char *known = m_known ? "" : "might ";
    if (m_arg)
      return warning_meta (rich_loc, m, get_controlling_option (),
                           "%sleak of unscrubbed data %qE", known, m_arg);
    else
      return warning_meta (rich_loc, m, get_controlling_option (),
                           "%sleak of unscrubbed data %qs", known,
                           "<unknown>");
  }

protected:
  int m_cwe;
  bool m_known;
};

class heap_data_leak : public data_leak
{
public:
  /* "CWE-244: Improper Clearing of Heap Memory Before Release ('Heap
   *  Inspection')". */
  static const int ID{ 244 };

  heap_data_leak (const sm_scrub &sm, tree arg, bool known = true)
      : data_leak (sm, arg, ID, known)
  {
  }

  const char *
  get_kind () const override
  {
    return "heap_data_leak";
  }

  label_text
  describe_state_change (const evdesc::state_change &change) final override
  {
    m_alloc_event = change.m_event_id;
    if (change.m_old_state == m_sm.get_start_state ()
        && heap_unscrubbed_p (change.m_new_state))
      {
        if (change.m_expr)
          return change.formatted_print ("%qE is allocated here",
                                         change.m_expr);
        else
          return change.formatted_print ("%qs is allocated here", "<unknown>");
      }
    return label_text ();
  }

  label_text
  describe_final_event (const evdesc::final_event &ev) override
  {
    const char *leak_certainty = m_known ? "leaks " : "might leak ";
    if (ev.m_expr)
      {
        if (m_alloc_event.known_p ())
          return ev.formatted_print ("%qE %shere; was allocated at %@",
                                     ev.m_expr, leak_certainty,
                                     &m_alloc_event);
        else
          return ev.formatted_print ("%qE %shere", ev.m_expr, leak_certainty);
      }
    else
      {
        if (m_alloc_event.known_p ())
          return ev.formatted_print ("%qs %qshere; was allocated at %@",
                                     "<unknown>", leak_certainty,
                                     &m_alloc_event);
        else
          return ev.formatted_print ("%qs %shere", "<unknown>",
                                     leak_certainty);
      }
  }

protected:
  diagnostic_event_id_t m_alloc_event;
};

class leak_on_realloc_with_move : public heap_data_leak
{
public:
  leak_on_realloc_with_move (const sm_scrub &sm, tree arg, bool known = true)
      : heap_data_leak (sm, arg, known)
  {
  }

  const char *
  get_kind () const override
  {
    return "leak_on_realloc_with_move";
  }

  label_text
  describe_final_event (const evdesc::final_event &ev) final override
  {
    const char *leak_certainty = m_known ? "leaks " : "might leak ";
    if (ev.m_expr)
      {
        if (m_alloc_event.known_p ())
          return ev.formatted_print ("%qE %shere (when realloc succeed and "
                                     "buffer is moved); was allocated at %@",
                                     ev.m_expr, leak_certainty,
                                     &m_alloc_event);
        else
          return ev.formatted_print (
              "%qE %sleaks here (when realloc succeed and buffer is moved)",
              ev.m_expr, leak_certainty);
      }
    else
      {
        if (m_alloc_event.known_p ())
          return ev.formatted_print ("%qs %qshere (when realloc succeed and "
                                     "buffer is moved); was allocated at %@",
                                     "<unknown>", leak_certainty,
                                     &m_alloc_event);
        else
          return ev.formatted_print (
              "%qs %shere (when realloc succeed and buffer is moved)",
              "<unknown>", leak_certainty);
      }
  }
};

class leak_on_realloc_free : public heap_data_leak
{
public:
  leak_on_realloc_free (const sm_scrub &sm, tree arg, bool known = true)
      : heap_data_leak (sm, arg, known)
  {
  }

  const char *
  get_kind () const override
  {
    return "leak_on_realloc_free";
  }

  label_text
  describe_final_event (const evdesc::final_event &ev) final override
  {
    const char *leak_certainty = m_known ? "leaks " : "might leak ";
    if (ev.m_expr)
      {
        if (m_alloc_event.known_p ())
          return ev.formatted_print (
              "%qE %shere (realloc call equivalent to free [c.f. realloc "
              "manual]); was allocated at %@",
              ev.m_expr, leak_certainty, &m_alloc_event);
        else
          return ev.formatted_print (
              "%qE %sleaks here (realloc call equivalent to free [c.f. "
              "realloc manual])",
              ev.m_expr, leak_certainty);
      }
    else
      {
        if (m_alloc_event.known_p ())
          return ev.formatted_print (
              "%qs %qshere (realloc call equivalent to free [c.f. realloc "
              "manual]); was allocated at %@",
              "<unknown>", leak_certainty, &m_alloc_event);
        else
          return ev.formatted_print ("%qs %shere (realloc call equivalent to "
                                     "free [c.f. realloc manual])",
                                     "<unknown>", leak_certainty);
      }
  }
};

class stack_data_leak : public data_leak
{
public:
  /* "CWE-226: Sensitive Information in Resource Not Removed Before Reuse" */
  static const int ID{ 226 };

  stack_data_leak (const sm_scrub &sm, tree arg, const region *reg,
                   bool known = true)
      : data_leak (sm, arg, ID, known), m_reg (reg)
  {
  }

  stack_data_leak (const sm_scrub &sm, tree arg, bool known = true)
      : data_leak (sm, arg, ID, known), m_reg (nullptr)
  {
  }

  const char *
  get_kind () const final override
  {
    return "stack_data_leak";
  }

  label_text
  describe_state_change (const evdesc::state_change &change) final override
  {

    if (DEBUG)
      {
        auto logger = m_sm.get_logger ();
        LOG_SCOPE (logger);
        string change_sm_name (change.m_event.m_sm.get_name ());
        if (change_sm_name == m_sm.get_name ())
          dump_state_change (logger, change);
        else if (logger)
          logger->log ("State change from other sm: %s",
                       change_sm_name.data ());
      }

    if (change.m_old_state == m_sm.get_start_state ())
      {
        if (stack_unscrubbed_p (change.m_new_state))
          {
            // Allocated through a call to alloca
            if (m_reg->get_kind () == RK_ALLOCA)
              return change.formatted_print ("%qE is allocated on stack here",
                                             change.m_expr);

            auto event = change.m_event;
            if (const gimple *stmt = event.m_stmt)
              if (const gcall *call = dyn_cast<const gcall *> (stmt))
                {
                  // TODO: move this inside of:
                  //  add_function_entry_event (const exploded_edge &eedge,
                  //                            checker_path *emission_path);
                  // also have a look at: describe_call_with_state()
                  call_details cd (call, event.m_dst_state.m_region_model,
                                   nullptr);
                  if (tree lhs = gimple_call_lhs (call))
                    {
                      if (same_tree_p (lhs, change.m_expr))
                        return change.formatted_print (
                            "Local variable %qE initialized here from a call "
                            "to "
                            "%qE",
                            m_arg, cd.get_fndecl_for_call ());
                    }
                  else
                    {
                      for (unsigned idx = 0; idx < cd.num_args (); idx++)
                        if (same_tree_p (cd.get_arg_tree (idx), change.m_expr))
                          return change.formatted_print (
                              "%qE passed as param %d through a call to %qE",
                              change.m_expr, idx + 1,
                              cd.get_fndecl_for_call ());
                    }
                }

            return change.formatted_print (
                "Local variable %qE initialized here", m_arg);
          }
      }

    return label_text ();
  }

  void
  mark_interesting_stuff (interesting_t *interest) final override
  {
    if (DEBUG)
      {
        auto logger = m_sm.get_logger ();
        LOG_SCOPE (logger);
        if (logger)
          {
            logger->start_log_line ();
            m_reg ? m_reg->dump_to_pp (logger->get_printer (), SIMPLE)
                  : logger->log_partial ("m_reg == nullptr");
            logger->end_log_line ();
          }
      }

    if (m_reg && m_reg->get_memory_space () == MEMSPACE_STACK)
      interest->add_region_creation (m_reg);
  }

  label_text
  describe_final_event (const evdesc::final_event &ev) final override
  {
    if (DEBUG)
      {
        auto logger = m_sm.get_logger ();
        LOG_SCOPE (logger);
        if (logger)
          dump_final_state (logger, ev);
      }

    const char *leak_certainty = m_known ? "leaks " : "might leak ";
    if (ev.m_expr)
      return ev.formatted_print ("%qE %shere", ev.m_expr, leak_certainty);
    else
      return ev.formatted_print ("%qs %shere", "<unknown>", leak_certainty);
  }

private:
  const region *m_reg;
  diagnostic_event_id_t m_alloc_event;
};

/* Implementation of class sm_scrub */

sm_scrub::sm_scrub (logger *logger)
    : state_machine (SM_NAME.data (), logger),
      m_scrubbed (state_machine::add_state ("scrubbed"))
{
  gcc_assert (m_start->get_id () == 0);
  gcc_assert (m_scrubbed->get_id () == 1);
  m_stack = add_state ("unscrubbed", resource_kind::RS_STACK);
  m_heap = add_state ("unscrubbed", resource_kind::RS_HEAP);
}

bool
sm_scrub::inherited_state_p () const
{
  return true;
}

sm_scrub::state_t
sm_scrub::alt_get_inherited_state (const sm_state_map &smap,
                                   const svalue *sval,
                                   const extrinsic_state &ext_state) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);

  if (DEBUG && logger)
    {
      logger->start_log_line ();
      sval->dump_to_pp (logger->get_printer (), SIMPLE);
      logger->end_log_line ();
    }

  switch (sval->get_kind ())
    {
    case SK_REGION:
      {
        auto reg_sval = sval->dyn_cast_region_svalue ();
        auto pointee = reg_sval->get_pointee ();
        if (pointee->get_kind () == RK_HEAP_ALLOCATED
            || pointee->get_kind () == RK_ALLOCA)
          return nullptr;
        auto state = smap.get_state (pointee, ext_state);
        return state;
      }
      break;
    case SK_INITIAL:
      {
        auto initial_sval = sval->dyn_cast_initial_svalue ();
        auto reg = initial_sval->get_region ();
        auto state = reg ? smap.get_state (reg, ext_state) : nullptr;
        return state;
      }
      break;
    default:
      break;
    }

  return nullptr;
}

sm_scrub::state_t
sm_scrub::alt_get_inherited_state (const sm_state_map &smap, const region *reg,
                                   const extrinsic_state &ext_state) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);

  if (DEBUG && logger)
    {
      logger->start_log_line ();
      reg->dump_to_pp (logger->get_printer (), SIMPLE);
      logger->end_log_line ();
    }

  if (reg->dyn_cast_frame_region ())
    return nullptr;
  else if (const symbolic_region *symbolic_reg
           = reg->dyn_cast_symbolic_region ())
    {
      if (const svalue *sval = symbolic_reg->get_pointer ())
        return smap.get_state (sval, ext_state);
    }
  else if (reg->dyn_cast_element_region ()
           && !any_pointer_p (reg->get_type ()))
    return nullptr;

  if (!reg->base_region_p ())
    {
      auto base_reg = reg->get_base_region ();
      return smap.get_state (base_reg, ext_state);
    }

  return nullptr;
}

/*
  This method should return true if the STMT holds a call to a function
  recognized by this state machine (c.f., gcc/analyzer/sm-fd.cc:1216) */
bool
sm_scrub::on_stmt (sm_context *sm_ctx, const supernode *node,
                   const gimple *stmt) const
{
  bool res = false;
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  if (const gcall *call = dyn_cast<const gcall *> (stmt))
    {
      if (const char *name = get_fn_identifier (sm_ctx, call))
        {
          call_kind kind = build_call_kind (name);
          if (kind == call_kind::None)
            res = on_call (sm_ctx, node, call);
          else
            res = on_known_fn_call (sm_ctx, node, call, kind);
        }
    }
  else if (const gassign *assign = dyn_cast<const gassign *> (stmt))
    handle_assign_stmt (sm_ctx, node, assign);
  return res;
}

bool
sm_scrub::can_purge_p (state_t state) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);
  auto res = !unscrubbed_p (state);
  if (DEBUG && logger)
    {
      logger->start_log_line ();
      logger->log_partial ("state: ");
      state->dump_to_pp (logger->get_printer ());
      logger->log_partial (" | returning: %s", res ? "true" : "false");
      logger->end_log_line ();
    }
  // TODO: this might break things with PARAM?
  return res;
}

void
sm_scrub::on_phi (sm_context *sm_ctx, const supernode *node, const gphi *phi,
                  tree rhs) const
{
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  auto model = sm_ctx->get_old_region_model ();
  for (unsigned idx = 0; idx < gimple_phi_num_args (phi); idx++)
    {
      auto arg = gimple_phi_arg_def (phi, idx);
      auto sval = model->get_rvalue (arg, nullptr);
      if (logger)
        {
          auto pp = logger->get_printer ();
          logger->start_log_line ();
          logger->log ("phi arg %d:", idx);
          logger->log_partial (" arg: ");
          dump_quoted_tree (logger->get_printer (), arg);
          logger->log_partial (" | sval: ");
          sval->dump_to_pp (pp, false);
          logger->end_log_line ();
        }
    }
}

void
sm_scrub::on_push_frame (sm_context *sm_ctx, const supernode *node,
                         const frame_region *callee_frame,
                         const gimple *call_instr) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);

  // Checking we're not working on the first frame
  if (callee_frame->get_index () != 0)
    {
      if (logger)
        {
          auto pp = logger->get_printer ();
          logger->start_log_line ();
          logger->log_partial ("Function ");
          dump_quoted_tree (pp, callee_frame->get_fndecl ());
          logger->log_partial (" called by ");
          dump_quoted_tree (pp,
                            callee_frame->get_calling_frame ()->get_fndecl ());
          logger->end_log_line ();
        }

      auto callee_fn_decl = callee_frame->get_fndecl ();

      // Checking if we have access to the declaration of the function
      // TODO => always true here, remove the condition
      if (callee_fn_decl)
        {
          // auto callee_fn = callee_frame->get_function ();
          // auto calling_frame = callee_frame->get_calling_frame ();
          auto model = sm_ctx->get_old_region_model ();
          // auto mgr = model->get_manager ();

          unsigned idx;
          tree parm_decl;
          call_details cd (dyn_cast<const gcall *> (call_instr),
                           const_cast<region_model *> (model), nullptr);
          // Iterating over the argument of callsite and function's
          // parameters
          for (idx = 0, parm_decl = DECL_ARGUMENTS (callee_fn_decl);
               idx < cd.num_args () && parm_decl;
               idx++, parm_decl = DECL_CHAIN (parm_decl))
            {

              auto arg = cd.get_arg_tree (idx);

              /* svalues are correctly handled by the analyzer iff svalues from
               *  caller is already tracked. Otherwise troubles are on the way.
               *  E.g.:
               *    void init (int *ptr) { *ptr = base_val; }
               *
               *    void main (void)
               *    {
               *      int SCRUB_ATTR x;
               *      init (&x);
               *    }
               */
              auto reduced_tree = reduce_tree (arg, logger);
              if (any_pointer_p (parm_decl)
                  // && check_state (sm_ctx, call_instr, arg, m_start)
                  && should_be_scrubbed (reduced_tree, logger, false))
                // FIXME: EXPLOSION - add an integer for max_depth to
                // reduce_tree()?
                {
                  // Tracking arg svalue and should also track for parm as
                  // we're dealing with pointer type here
                  auto arg_sval = cd.get_arg_svalue (idx);
                  // FIXME: keep this?
                  // Tracking arg region (hopefully a local for caller)
                  auto deref_reg
                      = model->deref_rvalue (arg_sval, arg, nullptr);

                  state_t targeted = get_corresponding_state (
                      deref_reg, reduced_tree, sm_ctx);
                  if (targeted == m_start)
                    {
                      if (logger)
                        logger->log ("targeted state == %qs, maybe a problem?",
                                     m_start->get_name ());
                      return;
                    }
                  else if (logger)
                    logger->log ("targeted state == %qs",
                                 targeted->get_name ());

                  /* FIXME: do this in on_push_frame might lead to issue with
                   * function without body (e.g., extern linkage function)
                   */
                  if (check_state (sm_ctx, call_instr, arg_sval, m_start))
                    sm_ctx->on_transition (node, call_instr, arg_sval, m_start,
                                           targeted);

                  // Only tracking region stack related, i.e., stack and
                  // parameters
                  if (check_state (sm_ctx, call_instr, deref_reg, m_start))
                    if (stack_memory_space_p (deref_reg))
                      sm_ctx->on_transition (node, call_instr, deref_reg,
                                             m_start, targeted, NULL_TREE);
                }
            }
        }
    }
  else if (logger)
    {
      logger->start_log_line ();
      logger->log_partial ("Initial function: ");
      dump_quoted_tree (logger->get_printer (), callee_frame->get_fndecl ());
      logger->end_log_line ();
    }
}

void
sm_scrub::on_pop_frame (sm_state_map *smap, const frame_region *frame_reg,
                        tree result_lvalue, const gimple *call,
                        sm_context *sm_ctx, const supernode *node) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);

  auto fn_decl = frame_reg->get_fndecl ();

  if (logger)
    {
      logger->start_log_line ();
      logger->log_partial ("Exiting function ");
      dump_quoted_tree (logger->get_printer (), fn_decl);
      logger->end_log_line ();
    }

  // Searching for the return stmt
  const greturn *ret_stmt = nullptr;
  basic_block bb;
  FOR_EACH_BB_FN (bb, frame_reg->get_function ())
  {
    gimple_stmt_iterator si;
    for (si = gsi_start_bb (bb); !ret_stmt && !gsi_end_p (si); gsi_next (&si))
      if (greturn *return_stmt = dyn_cast<greturn *> (gsi_stmt (si)))
        ret_stmt = return_stmt;
  }
  if (logger)
    {
      if (ret_stmt)
        {
          auto pp = logger->get_printer ();
          logger->start_log_line ();
          logger->log_partial ("ret_stmt: ");
          pp_begin_quote (pp, pp_show_color (pp));
          pp_gimple_stmt_1 (pp, ret_stmt, 0, (dump_flags_t)0);
          pp_end_quote (pp, pp_show_color (pp));
          logger->end_log_line ();
        }
      else
        logger->log ("No ret_stmt");
    }

  for (sm_state_map::reg_iterator_t iter = smap->reg_begin ();
       iter != smap->reg_end (); ++iter)
    {
      auto reg = (*iter).first;
      auto &entry = (*iter).second;

      if (logger)
        {
          auto pp = logger->get_printer ();
          logger->start_log_line ();
          logger->log_partial ("region: ");
          reg->dump_to_pp (pp, false);
          logger->log_partial (" | state: (%qs)", entry.m_state->get_name ());
          logger->end_log_line ();
        }

      const element_region *elm_reg = reg->dyn_cast_element_region ();
      const decl_region *decl_reg
          = reg->dyn_cast_decl_region () ? reg->dyn_cast_decl_region ()
            : elm_reg
                ? elm_reg->get_base_region ()
                      ? elm_reg->get_base_region ()->dyn_cast_decl_region ()
                      : nullptr
                : nullptr;

      if (decl_reg)
        {
          if (logger)
            logger->log ("Considering this region");

          auto considered_reg
              = elm_reg ? (const region *)elm_reg : (const region *)decl_reg;

          if (decl_reg->get_parent_region () == frame_reg)
            {
              if (stack_unscrubbed_p (entry.m_state))
                {
                  auto considered_tree
                      = sm_ctx->get_old_region_model ()
                            ->get_representative_tree (considered_reg);
                  auto diag_var = sm_ctx->get_diagnostic_tree (
                      considered_tree ? considered_tree
                                      : decl_reg->maybe_get_decl ());
                  sm_ctx->warn (node, ret_stmt, diag_var,
                                make_unique<stack_data_leak> (*this, diag_var,
                                                              considered_reg));
                }
              if (logger)
                {
                  auto pp = logger->get_printer ();
                  logger->start_log_line ();
                  logger->log_partial ("Clearing any state for: ");
                  decl_reg->dump_to_pp (pp, false);
                  logger->end_log_line ();
                }
            }
        }
      /* This loop detect any local region to FRAME_REG within SMAP
       *        (i.e. looping until parent.get_kind () == RK_FRAME)
       */
      /* FIXME: Not using it for warning emission for now as it might lead to
       *         an explosion of false positive for structures
       */
      auto parent = reg->get_parent_region ();
      while (parent && parent->get_kind () != RK_FRAME)
        parent = parent->get_parent_region ();
      if (parent == frame_reg)
        smap->clear_any_state (reg);
    }
}

std::unique_ptr<pending_diagnostic>
sm_scrub::on_leak (tree var, const svalue *sval,
                   const sm_context *sm_ctx) const
{
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  if (logger)
    {
      logger->start_log_line ();
      logger->log_partial ("var: ");
      var ? dump_quoted_tree (logger->get_printer (), var)
          : logger->log_partial ("NULL_TREE");
      logger->end_log_line ();
    }
  if (var && any_pointer_p (var))
    {
      auto sval_eq_null = is_null (sm_ctx, sval);
      if (!sval_eq_null.is_true ())
        {
          const region *deref_reg
              = sm_ctx->get_old_region_model ()->deref_rvalue (sval, var,
                                                               nullptr);
          var = const_cast<sm_context *> (sm_ctx)->get_diagnostic_tree (var);
          switch (deref_reg->get_kind ())
            {
            case RK_ALLOCA:
              {
                auto reduced_var = reduce_tree (var, nullptr);
                if (TREE_CODE (reduced_var) == VAR_DECL
                    && DECL_CONTEXT (reduced_var) == cfun->decl)
                  return make_unique<stack_data_leak> (
                      *this, var,
                      sm_ctx->get_old_region_model ()->get_lvalue (var,
                                                                   nullptr));
              }
              break;
            // case RK_DECL:
            //   {
            //     if (tree decl = deref_reg->maybe_get_decl ())
            //       if (DECL_CONTEXT (decl) == cfun->decl)
            //         return make_unique<stack_data_leak> (*this, var,
            //                                              deref_reg);
            //   }
            //   break;
            case RK_HEAP_ALLOCATED:
              {
                return make_unique<heap_data_leak> (*this, var,
                                                    sval_eq_null.is_known ());
              }
            default:
              // TODO: logging
              break;
            }
        }
    }
  return nullptr;
}

void
sm_scrub::on_realloc_with_move (region_model *model, sm_state_map *smap,
                                const svalue *old_ptr_sval,
                                const svalue *new_ptr_sval,
                                const extrinsic_state &ext_state,
                                sm_context *sm_ctx,
                                const call_details &cd) const
{
  logger *logger = get_logger ();
  LOG_SCOPE (logger);

  /* We do not want to emit any warning in the realloc free equivalent case
   * (i.e., if ptr is not null and size is equal to zero)
   * old_ptr_sval cannot be null as we're in the realloc with move case.
   */
  if (cd.get_arg_svalue (1)->all_zeroes_p ())
    return;

  auto call = cd.get_call_stmt ();
  auto old_state = sm_ctx->get_state (call, old_ptr_sval);
  if (logger)
    {
      logger->log ("old_ptr_sval state: %s", old_state->get_name ());
      if (DEBUG)
        {
          auto pp = logger->get_printer ();
          logger->start_log_line ();
          logger->log_partial ("old_ptr_sval: ");
          old_ptr_sval->dump_to_pp (pp, false);
          logger->end_log_line ();
          logger->start_log_line ();
          logger->log_partial ("new_ptr_sval: ");
          new_ptr_sval->dump_to_pp (pp, false);
          logger->end_log_line ();
        }
    }
  if (heap_unscrubbed_p (old_state))
    {
      auto node = ext_state.get_engine ()
                      ->get_supergraph ()
                      ->get_supernode_for_stmt (call);
      auto var = sm_ctx->get_diagnostic_tree (cd.get_arg_tree (0));
      sm_ctx->warn (node, call, var,
                    make_unique<leak_on_realloc_with_move> (*this, var));
      sm_ctx->on_transition (node, call, old_ptr_sval, m_heap, m_start);
      sm_ctx->on_transition (node, call, new_ptr_sval, m_start, m_heap);
    }
}

/*
  This function returns the function name */
const char *
sm_scrub::get_fn_identifier (sm_context *sm_ctx, const gcall *call) const
{
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  if (tree fn_decl = sm_ctx->get_fndecl_for_call (call))
    if (tree fn_name = DECL_NAME (fn_decl))
      if (const char *name = IDENTIFIER_POINTER (fn_name))
        {
          if (logger)
            logger->log ("Found function %qs", name);
          return name;
        }
  return nullptr;
}

void
sm_scrub::on_allocator (sm_context *sm_ctx, const supernode *node,
                        const gcall *call, const resource_kind rk) const
{
  gcc_assert (rk == resource_kind::RS_HEAP || rk == resource_kind::RS_STACK);
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  if (tree lhs = gimple_call_lhs (call))
    if (should_be_scrubbed (lhs, get_logger ()))
      switch (rk)
        {
        case resource_kind::RS_HEAP:
          sm_ctx->on_transition (node, call, lhs, m_start, m_heap);
          break;
        case resource_kind::RS_STACK:
          sm_ctx->on_transition (node, call, lhs, m_start, m_stack);
          break;
        default:
          gcc_unreachable ();
        }
}

void
sm_scrub::on_realloc (sm_context *sm_ctx, const supernode *node,
                      const gcall *call) const
{
  /* Checking if the current call is an equivalent to free, i.e., the requested
   * size is zero and the memory object is not null
   */
  auto model = sm_ctx->get_old_region_model ();
  call_details cd (call, const_cast<region_model *> (model), nullptr);
  auto ptr_sval = cd.get_arg_svalue (0);
  auto ptr_tree = cd.get_arg_tree (0);
  auto ptr_eq_null = is_null (sm_ctx, ptr_sval);
  auto ptr_state = sm_ctx->get_state (call, ptr_sval);
  auto size_sval = cd.get_arg_svalue (1);

  if (ptr_eq_null.is_false () && size_sval->all_zeroes_p ()
      && heap_unscrubbed_p (ptr_state))
    {
      tree fixed_tree = sm_ctx->get_diagnostic_tree (ptr_tree);
      sm_ctx->warn (node, call, ptr_tree,
                    make_unique<leak_on_realloc_free> (
                        *this, fixed_tree ? fixed_tree : ptr_tree));
      sm_ctx->set_next_state (call, ptr_sval, m_start);
    }
}

sm_scrub::state_t
sm_scrub::get_corresponding_state (const region *reg, tree t,
                                   sm_context *sm_ctx) const
{

  fprintf(stderr, ">>> Inside get_corresponding_state!!!!\n");
  auto logger = get_logger ();
  LOG_SCOPE (logger);
  if (t && sm_ctx && !reg)
    reg = sm_ctx->get_old_region_model ()->get_lvalue (t, nullptr);

  if (reg)
    {
      auto res = m_stack;
      if (heap_memory_space_p (reg, sm_ctx))
        res = m_heap;
      else if (t && parm_decl_p (t))
        res = m_param;
      if (logger)
        {
          logger->start_log_line ();
          logger->log_partial ("tree: ");
          t ? logger->log_partial ("%qE", t)
            : logger->log_partial ("NULL_TREE");
          logger->log_partial (" | reg: ");
          reg->dump_to_pp (logger->get_printer (), SIMPLE);
          logger->log_partial (" | corresponding state: %s(%s)",
                               res->get_name (),
                               res == m_stack   ? "stack"
                               : res == m_heap  ? "heap"
                               : res == m_param ? "param"
                               : res == m_start ? "start"
                                                : "unknown");
          logger->end_log_line ();
        }
      return res;
    }

  return m_start;
}

void
sm_scrub::on_memset (sm_context *sm_ctx, const supernode *node,
                     const gcall *call) const
{ 
  fprintf(stderr, ">>> [SCRUB DEBUG] Entered memset!!!!\n");
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  region_model *model = sm_ctx->get_new_program_state ()->m_region_model;
  call_details cd (call, model, nullptr);

  // Checking for direct pointer usage
  auto ptr_sval = cd.get_arg_svalue (0);
  auto sval_state = sm_ctx->get_state (call, ptr_sval);
  // Set next state to SCRUBBED iff tracked as UNSCRUBBED
  if (unscrubbed_p (sval_state))
    sm_ctx->on_transition (node, call, ptr_sval, sval_state, m_scrubbed);

  // Checking for MEM_REF usage (e.g., '&array')
  auto ptr_reg
      = sm_ctx->get_new_program_state ()->m_region_model->deref_rvalue (
          ptr_sval, NULL_TREE, nullptr);
  auto reg_state = sm_ctx->get_state (call, ptr_reg);
  // Set next state to SCRUBBED iff tracked as UNSCRUBBED
  if (unscrubbed_p (reg_state))
    sm_ctx->on_transition (node, call, ptr_reg, reg_state, m_scrubbed,
                           NULL_TREE);
}

void
sm_scrub::on_memcpy (sm_context *sm_ctx, const supernode *node,
                     const gcall *call) const
{ 
  fprintf(stderr, ">>> [SCRUB DEBUG] Entered memcpy!!!!\n");
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  region_model *model = sm_ctx->get_new_program_state ()->m_region_model;
  call_details cd (call, model, nullptr);
  auto src_sval = cd.get_arg_svalue (1);
  auto src_tree = cd.get_arg_tree (1);
  auto src_eq_null = is_null (sm_ctx, src_sval);
  auto src_state = sm_ctx->get_state (call, src_sval);
  auto dst_sval = cd.get_arg_svalue (0);
  auto dst_tree = cd.get_arg_tree (0);
  auto dst_eq_null = is_null (sm_ctx, dst_sval);
  auto src_eq_dst = sm_ctx->get_old_region_model ()->eval_condition (
      src_sval, EQ_EXPR, dst_sval);
  auto dst_state = sm_ctx->get_state (call, dst_sval);
  
  
  if (DEBUG && logger)
    {
      fprintf(stderr, ">>> [SCRUB DEBUG] Entered memcpy check loop\n");
      auto pp = logger->get_printer ();
      logger->start_log_line ();
      logger->log_partial ("src_tree: ");
      dump_quoted_tree (pp, src_tree);
      logger->log_partial (" | state: %s | src_sval: ",
                           src_state->get_name ());
      src_sval->dump_to_pp (pp, false);
      logger->end_log_line ();
      logger->start_log_line ();
      logger->log_partial ("dst_tree: ");
      dump_quoted_tree (pp, dst_tree);
      logger->log_partial (" | state: %s | dst_sval: ",
                           dst_state->get_name ());
      dst_sval->dump_to_pp (pp, false);
      logger->end_log_line ();
    }

  if (!src_eq_null.is_true () && !dst_eq_null.is_true ()
      && !src_eq_dst.is_true () && unscrubbed_p (src_state))
    {
      // if DST was already tracked, keep the same state, otherwise find the
      // appropriate one.
      dst_state = unscrubbed_p (dst_state)
                      ? dst_state
                      : get_corresponding_state (nullptr, dst_tree, sm_ctx);
      // if DST is a pointer to a region on stack, then mark the DEREF_REG
      if (stack_unscrubbed_p (dst_state))
        {
          if (const region *deref_reg
              = model->deref_rvalue (dst_sval, dst_tree, nullptr))
            {
              sm_ctx->set_next_state (call, deref_reg, dst_state, src_tree);
              return;
            }
        }
      sm_ctx->set_next_state (call, dst_sval, dst_state, src_tree);
    }
}

void
sm_scrub::on_free (sm_context *sm_ctx, const supernode *node,
                   const gcall *call) const
{
  // TODO: 1PB with free on intraprocedural/*/structure.c
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  region_model *model = sm_ctx->get_new_program_state ()->m_region_model;
  call_details cd (call, model, nullptr);
  auto ptr_sval = cd.get_arg_svalue (0);
  auto ptr_tree = cd.get_arg_tree (0);
  auto ptr_eq_null = is_null (sm_ctx, ptr_sval);
  auto ptr_state = sm_ctx->get_state (call, ptr_sval);

  if (DEBUG && logger)
    {
      auto pp = logger->get_printer ();
      logger->start_log_line ();
      logger->log_partial ("ptr_tree: ");
      dump_quoted_tree (pp, ptr_tree);
      logger->log_partial (" | state: %s | ptr_sval: ",
                           ptr_state->get_name ());
      ptr_sval->dump_to_pp (pp, false);
      logger->end_log_line ();
    }

  if (!ptr_eq_null.is_true () && heap_unscrubbed_p (ptr_state))
    {
      tree fixed_tree = sm_ctx->get_diagnostic_tree (ptr_tree);
      sm_ctx->warn (node, call, ptr_tree,
                    make_unique<heap_data_leak> (
                        *this, fixed_tree ? fixed_tree : ptr_tree,
                        ptr_eq_null.is_known ()));
      sm_ctx->set_next_state (call, ptr_sval, m_start);
    }
}

bool
sm_scrub::on_call (sm_context *sm_ctx, const supernode *node,
                   const gcall *call) const
{
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  region_model *model = sm_ctx->get_new_program_state ()->m_region_model;
  call_details cd (call, model, nullptr);
  if (const char *fn_name = get_fn_identifier (sm_ctx, call))
    {
      if (scrubbers.contains (fn_name))
        on_scrubber (sm_ctx, node, cd, fn_name);
      else
        {
          // Case where LHS has to be scrubbed
          if (tree lhs = gimple_call_lhs (call))
            if (tree reduced_lhs = reduce_tree (lhs, logger))
              if (should_be_scrubbed (reduced_lhs, logger, false))
                {
                  auto corresponding_state
                      = get_corresponding_state (nullptr, lhs, sm_ctx);
                  sm_ctx->set_next_state (call, lhs, corresponding_state,
                                          NULL_TREE, !any_pointer_p (lhs));
                }
          /* Case where one of the argument have the scrub attribute but has
           * not been seen yet
           */
          for (unsigned idx = 0; idx < cd.num_args (); idx++)
            {
              auto arg_tree = cd.get_arg_tree (idx);
              auto reduced_tree = reduce_tree (arg_tree, logger);
              if (should_be_scrubbed (reduced_tree, logger, false))
                {
                  auto state = get_corresponding_state (nullptr, reduced_tree,
                                                        sm_ctx);
                  sm_ctx->on_transition (node, call, reduced_tree, m_start,
                                         state, NULL_TREE,
                                         !any_pointer_p (reduced_tree));
                }
            }
        }
    }

  return true;
}

void
sm_scrub::on_scrubber (sm_context *sm_ctx, const supernode *node,
                       call_details &cd, const char *scrubber_name) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);

  auto model = sm_ctx->get_old_region_model ();
  if (logger)
    {
      logger->log ("Found a call to scrubber fn: %qs",
                   scrubber_name ? scrubber_name : "<anonymous_fn>");
    }

  for (unsigned idx = 0; idx < cd.num_args (); idx++)
    {
      auto arg_sval = cd.get_arg_svalue (idx);
      const region *arg_reg = nullptr;
      auto arg_tree = cd.get_arg_tree (idx);
      // auto reduced_arg = reduce_tree (arg_tree, nullptr);
      state_t sval_state = m_start, reg_state = m_start;
      if (any_pointer_p (arg_sval))
        {
          sval_state = sm_ctx->get_state (cd.get_call_stmt (), arg_sval);
          if (arg_sval && unscrubbed_p (sval_state))
            sm_ctx->on_transition (node, cd.get_call_stmt (), arg_sval,
                                   sval_state, m_scrubbed);
          arg_reg = model->deref_rvalue (arg_sval, arg_tree, nullptr);
        }
      // TODO: maybe this code? for case such as 'fn (some_int)'
      // if (!arg_reg)
      //   arg_reg =
      //   sm_ctx->get_old_region_model()->get_lvalue(arg_tree);
      if (arg_reg)
        {
          reg_state = sm_ctx->get_state (cd.get_call_stmt (), arg_reg);
          if (unscrubbed_p (reg_state))
            sm_ctx->on_transition (node, cd.get_call_stmt (), arg_reg,
                                   reg_state, m_scrubbed, NULL_TREE);
        }
      // if we are dealing with an array, check elements
      // TODO: currently issue when rebuilding the elm_reg, it does not
      // match any region in the sm_state_map for some reason if
      // (TREE_CODE (arg_reg->get_type ()) == ARRAY_TYPE)
      //   {
      //     auto mgr = sm_ctx->get_old_region_model ()->get_manager
      //     (); auto elm_type = TREE_TYPE (TREE_TYPE
      //     (arg_reg->get_type ())); if (tree index_domain =
      //     TYPE_DOMAIN (arg_reg->get_type ()))
      //       if (tree higher_bound = TYPE_MAX_VALUE (index_domain))
      //         {
      //           auto min_idx
      //               = tree_to_uhwi (TYPE_MIN_VALUE (index_domain));
      //           auto max_idx = tree_to_uhwi (higher_bound);
      //           auto array_tree
      //               = sm_ctx->get_old_region_model ()
      //                     ->get_representative_tree (arg_reg);
      //           for (unsigned long idx = min_idx; idx <= max_idx;
      //                idx++)
      //             {
      //               auto idx_tree
      //                   = build_int_cstu (integer_type_node, idx);
      //               auto cst_sval
      //                   = mgr->get_or_create_constant_svalue (
      //                       idx_tree);
      //               auto elm_reg = mgr->get_element_region (
      //                   arg_reg, elm_type, cst_sval);
      //               auto state = sm_ctx->get_state (call, elm_reg);
      //               if (logger)
      //                 {
      //                   auto pp = logger->get_printer ();
      //                   logger->start_log_line ();
      //                   logger->log_partial ("elm_reg: ");
      //                   elm_reg->dump_to_pp (pp, false);
      //                   logger->log_partial (" | simple: ");
      //                   elm_reg->dump_to_pp (pp, true);
      //                   logger->log_partial (
      //                       " | pointer: %p | state: ", elm_reg);
      //                   state->dump_to_pp (pp);
      //                   logger->end_log_line ();
      //                 }
      //               if (stack_unscrubbed_p (state))
      //                 sm_ctx->on_transition (node, call, elm_reg,
      //                                        state, m_start,
      //                                        NULL_TREE);
      //             }
      //         }
      //   }
      if (logger)
        {
          auto pp = logger->get_printer ();
          logger->start_log_line ();
          logger->log_partial ("idx: %d |  arg_tree: ", idx);
          dump_tree (pp, arg_tree);
          logger->log_partial (" | arg_sval: ");
          if (arg_sval)
            {
              arg_sval->dump_to_pp (pp, false);
              logger->log_partial (" | sval_state: %s",
                                   sval_state->get_name ());
            }
          else
            logger->log_partial ("nullptr");
          logger->log_partial (" | arg_reg: ");
          if (arg_reg)
            {
              arg_reg->dump_to_pp (pp, false);
              logger->log_partial ("| reg_state: %s", reg_state->get_name ());
            }
          else
            logger->log_partial ("nullptr");
          logger->end_log_line ();
        }
    }
}

bool
sm_scrub::on_known_fn_call (sm_context *sm_ctx, const supernode *node,
                            const gcall *call, const call_kind kind) const
{
  switch (kind)
    {
    case call_kind::Malloc:
      on_allocator (sm_ctx, node, call, resource_kind::RS_HEAP);
      break;
    case call_kind::Alloca:
      on_allocator (sm_ctx, node, call, resource_kind::RS_STACK);
      break;
    case call_kind::Realloc:
      on_realloc (sm_ctx, node, call);
      break;
    case call_kind::Free:
      on_free (sm_ctx, node, call);
      break;
    case call_kind::Memset:
      on_memset (sm_ctx, node, call);
      break;
    case call_kind::Memcpy:
      on_memcpy (sm_ctx, node, call);
      break;
    default:
      gcc_unreachable ();
    }
  return true;
}

void
sm_scrub::handle_assign_stmt (sm_context *sm_ctx, const supernode *node,
                              const gassign *assign) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);
  /* Checking if stmt is a clobbing one, i.e., a destructor of a local array or
   * structure.
   * // TODO: Maybe trigger leak for array and structure here?
   */
  if (tree rhs1 = gimple_assign_rhs1 (assign))
    if (!TREE_CLOBBER_P (rhs1))
      if (tree lhs = gimple_assign_lhs (assign))
        {
          auto reduced_lhs = reduce_tree (lhs, logger);
          /* Case where the reduced tree of LHS have the scrub attribute */
          if (should_be_scrubbed (reduced_lhs, get_logger (), false))
            if (check_state (sm_ctx, assign, lhs, m_start))
              {
                auto old_model = sm_ctx->get_old_region_model ();
                auto new_model
                    = sm_ctx->get_new_program_state ()->m_region_model;
                /* Dealing with a pointer*/
                if (any_pointer_p (lhs))
                  {
                    if (const svalue *assign_sval
                        = new_model->get_gassign_result (assign, nullptr))
                      if (const region_svalue *reg_sval
                          = assign_sval->dyn_cast_region_svalue ())
                        if (const region *pointee = reg_sval->get_pointee ())
                          {
                            switch (pointee->get_memory_space ())
                              {
                              case MEMSPACE_HEAP:
                                sm_ctx->on_transition (node, assign,
                                                       assign_sval, m_start,
                                                       m_heap);
                                break;
                              case MEMSPACE_STACK:
                                sm_ctx->on_transition (node, assign,
                                                       assign_sval, m_start,
                                                       m_stack);
                                break;
                              default:
                                {
                                  // TODO: logging
                                }
                                break;
                              }
                          }
                  }
                /* Dealing with non-pointer */
                else
                  {
                    if (const region *reg
                        = old_model->get_lvalue (reduced_lhs, nullptr))
                      {
                        switch (reg->get_memory_space ())
                          {
                          case MEMSPACE_STACK:
                            sm_ctx->on_transition (node, assign, lhs, m_start,
                                                   m_stack, NULL_TREE,
                                                   !any_pointer_p (lhs));
                            break;
                          case MEMSPACE_HEAP:
                            /* This should never happen here as we know
                             * that:
                             *  - any_pointer_p (lhs) == false
                             *  - we took the region of lhs
                             * => hence it cannot be on heap, but it could
                             *   totally be a global for example
                             */
                            /* FALLTHROUGH */
                          default:
                            {
                              // TODO: logging
                            }
                            break;
                          }
                      }
                  }
              }
          if (is_scrubbing_assignment (sm_ctx, assign))
            on_scrubbing_assignment (sm_ctx, node, assign, lhs, reduced_lhs);
          else
            propagate (sm_ctx, node, assign, lhs, reduced_lhs);
        }
}

void
sm_scrub::propagate (sm_context *sm_ctx, const supernode *node,
                     const gassign *assign, tree lhs, tree reduced_lhs) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);
  gcc_assert (lhs);

  auto new_model = sm_ctx->get_new_program_state ()->m_region_model;

  if (!any_pointer_p (lhs))
    {
      const region *lhs_reg = new_model->get_lvalue (lhs, nullptr);
      const svalue *lhs_sval = new_model->get_rvalue (reduced_lhs, nullptr);
      if (const cast_region *casted_reg = lhs_reg->dyn_cast_cast_region ())
        lhs_reg = casted_reg->get_base_region ();
      auto lhs_current_state = lhs_sval ? sm_ctx->get_state (assign, lhs_sval)
                                        : sm_ctx->get_state (assign, lhs_reg);
      auto corresponding_state
          = get_corresponding_state (nullptr, lhs, sm_ctx);
      auto maybe_scrub_lhs = !maybe_scrub (lhs, reduced_lhs)
                             && unscrubbed_p (lhs_current_state);
      auto rhs_untracked = false;
      if (tree rhs1 = gimple_assign_rhs1 (assign))
        {
          if (tree reduced_rhs1 = reduce_tree (rhs1, logger))
            {
              // TODO: issue with full propagation some times here
              auto considered_rhs
                  = FULL_PROPAGATION && var_decl_p (reduced_rhs1)
                        ? reduced_rhs1
                        : rhs1;
              if (state_t state = sm_ctx->get_state (
                      assign, considered_rhs, !any_pointer_p (considered_rhs)))
                {
                  if (logger)
                    {
                      const region *rhs_reg
                          = new_model->get_lvalue (reduced_rhs1, nullptr);
                      log_rhs (logger, 1, rhs1, rhs_reg, state, reduced_rhs1);
                    }
                  if (unscrubbed_p (state))
                    {
                      if (TREE_CODE (lhs) == MEM_REF)
                        {
                          auto new_lhs_sval
                              = new_model->get_manager ()->get_ptr_svalue (
                                  TREE_TYPE (reduced_lhs), lhs_reg);
                          if (logger)
                            {
                              logger->start_log_line ();
                              logger->log_partial ("Found a MEM_REF on "
                                                   "LHS, new_lhs_sval: ");
                              new_lhs_sval->dump_to_pp (logger->get_printer (),
                                                        SIMPLE);
                              logger->end_log_line ();
                            }
                          sm_ctx->on_transition (node, assign, new_lhs_sval,
                                                 m_start, corresponding_state,
                                                 reduced_rhs1);
                        }
                      else if (heap_unscrubbed_p (corresponding_state))
                        sm_ctx->on_transition (node, assign, lhs_sval, m_start,
                                               corresponding_state,
                                               reduced_rhs1);
                      else
                        {
                          auto to_track
                              = named_ssa_p (lhs) ? SSA_NAME_VAR (lhs) : lhs;
                          sm_ctx->on_transition (node, assign, to_track,
                                                 m_start, corresponding_state,
                                                 reduced_rhs1, true);
                          /* If assignment from a tracked anonym ssa,
                           * untrack it to avoid false positive */
                          if (anonym_ssa_p (reduced_rhs1))
                            sm_ctx->set_next_state (
                                assign, reduced_rhs1, m_start, nullptr,
                                !any_pointer_p (reduced_rhs1));
                        }
                    }
                  else if (maybe_scrub_lhs && !rhs_untracked)
                    rhs_untracked = true;
                }
              // if (any_pointer_p (reduced_rhs1))
              //   if (const svalue *sval
              //       = new_model->get_rvalue (reduced_rhs1, nullptr))
              //     if (auto state = sm_ctx->get_state (assign, sval))
              //       if (unscrubbed_p (state))
              //         sm_ctx->set_next_state (assign, lhs,
              //         corresponding_state,
              //                                 reduced_rhs1,
              //                                 !any_pointer_p (lhs));
            }
        }
      if (tree rhs2 = gimple_assign_rhs2 (assign))
        {
          if (tree reduced_rhs2 = reduce_tree (rhs2, logger))
            {
              auto considered_rhs
                  = FULL_PROPAGATION && var_decl_p (reduced_rhs2)
                        ? reduced_rhs2
                        : rhs2;
              if (state_t state = sm_ctx->get_state (
                      assign, considered_rhs, !any_pointer_p (considered_rhs)))
                {
                  if (logger)
                    {
                      const region *rhs_reg
                          = new_model->get_lvalue (reduced_rhs2, nullptr);
                      log_rhs (logger, 1, rhs2, rhs_reg, state, reduced_rhs2);
                    }
                  if (unscrubbed_p (state))
                    {
                      if (TREE_CODE (lhs) == MEM_REF)
                        {
                          auto new_lhs_sval
                              = new_model->get_manager ()->get_ptr_svalue (
                                  TREE_TYPE (reduced_lhs), lhs_reg);
                          if (logger)
                            {
                              logger->start_log_line ();
                              logger->log_partial ("Found a MEM_REF on "
                                                   "LHS, new_lhs_sval: ");
                              new_lhs_sval->dump_to_pp (logger->get_printer (),
                                                        SIMPLE);
                              logger->end_log_line ();
                            }
                          sm_ctx->on_transition (node, assign, new_lhs_sval,
                                                 m_start, corresponding_state,
                                                 reduced_rhs2);
                        }
                      else if (heap_unscrubbed_p (corresponding_state))
                        sm_ctx->on_transition (node, assign, lhs_sval, m_start,
                                               corresponding_state,
                                               reduced_rhs2);
                      else
                        {
                          auto to_track
                              = named_ssa_p (lhs) ? SSA_NAME_VAR (lhs) : lhs;
                          sm_ctx->on_transition (node, assign, to_track,
                                                 m_start, corresponding_state,
                                                 reduced_rhs2, true);
                          /* If assignment from a tracked anonym ssa,
                           * untrack it to avoid false positive */
                          if (anonym_ssa_p (reduced_rhs2))
                            sm_ctx->set_next_state (
                                assign, reduced_rhs2, m_start, nullptr,
                                !any_pointer_p (reduced_rhs2));
                        }
                    }
                  else if (maybe_scrub_lhs && !rhs_untracked)
                    rhs_untracked = true;
                }
            }
        }
      if (tree rhs3 = gimple_assign_rhs3 (assign))
        {
          if (tree reduced_rhs3 = reduce_tree (rhs3, logger))
            {
              auto considered_rhs
                  = FULL_PROPAGATION && var_decl_p (reduced_rhs3)
                        ? reduced_rhs3
                        : rhs3;
              if (state_t state = sm_ctx->get_state (
                      assign, considered_rhs, !any_pointer_p (considered_rhs)))
                {
                  if (logger)
                    {
                      const region *rhs_reg
                          = new_model->get_lvalue (reduced_rhs3, nullptr);
                      log_rhs (logger, 1, rhs3, rhs_reg, state, reduced_rhs3);
                    }
                  if (unscrubbed_p (state))
                    {
                      if (TREE_CODE (lhs) == MEM_REF)
                        {
                          auto new_lhs_sval
                              = new_model->get_manager ()->get_ptr_svalue (
                                  TREE_TYPE (reduced_lhs), lhs_reg);
                          if (logger)
                            {
                              logger->start_log_line ();
                              logger->log_partial ("Found a MEM_REF on "
                                                   "LHS, new_lhs_sval: ");
                              new_lhs_sval->dump_to_pp (logger->get_printer (),
                                                        SIMPLE);
                              logger->end_log_line ();
                            }
                          sm_ctx->on_transition (node, assign, new_lhs_sval,
                                                 m_start, corresponding_state,
                                                 reduced_rhs3);
                        }
                      else if (heap_unscrubbed_p (corresponding_state))
                        sm_ctx->on_transition (node, assign, lhs_sval, m_start,
                                               corresponding_state,
                                               reduced_rhs3);
                      else
                        {
                          auto to_track
                              = named_ssa_p (lhs) ? SSA_NAME_VAR (lhs) : lhs;
                          sm_ctx->on_transition (node, assign, to_track,
                                                 m_start, corresponding_state,
                                                 reduced_rhs3, true);
                          /* If assignment from a tracked anonym ssa,
                           * untrack it to avoid false positive */
                          if (anonym_ssa_p (reduced_rhs3))
                            sm_ctx->set_next_state (
                                assign, reduced_rhs3, m_start, nullptr,
                                !any_pointer_p (reduced_rhs3));
                        }
                    }
                  else if (maybe_scrub_lhs && !rhs_untracked)
                    rhs_untracked = true;
                }
            }
        }

      if (maybe_scrub_lhs && rhs_untracked)
        on_scrubbing_assignment (sm_ctx, node, assign, lhs, reduced_lhs);

      if (logger)
        {
          auto pp = logger->get_printer ();
          logger->start_log_line ();
          logger->log_partial ("lhs: ");
          dump_quoted_tree (pp, lhs);
          logger->log_partial (" | reduced_lhs: ");
          dump_quoted_tree (pp, reduced_lhs);
          logger->log_partial (" | lhs_reg: ");
          lhs_reg ? lhs_reg->dump_to_pp (pp, SIMPLE)
                  : logger->log_partial ("nullptr");

          logger->log_partial (" | lhs_sval: ");
          lhs_sval ? lhs_sval->dump_to_pp (pp, SIMPLE)
                   : logger->log_partial ("nullptr");
          logger->log_partial (" | lhs_current_state: %s",
                               lhs_current_state->get_name ());
          logger->end_log_line ();
        }
    }
}

bool
sm_scrub::is_scrubbing_assignment (sm_context *sm_ctx,
                                   const gassign *assign) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);
  auto lhs = gimple_assign_lhs (assign);
  auto reduced_lhs = reduce_tree (lhs, nullptr);
  if (maybe_scrub (lhs, reduced_lhs))
    return false;
  auto rhs1 = reduce_tree (gimple_assign_rhs1 (assign), nullptr);
  auto rhs2 = reduce_tree (gimple_assign_rhs2 (assign), nullptr);
  auto rhs3 = reduce_tree (gimple_assign_rhs3 (assign), nullptr);
  auto rhs1_state
      = rhs1 ? sm_ctx->get_state (assign, rhs1, !any_pointer_p (rhs1))
             : m_start;
  auto rhs2_state
      = rhs2 ? sm_ctx->get_state (assign, rhs2, !any_pointer_p (rhs2))
             : m_start;
  auto rhs3_state
      = rhs3 ? sm_ctx->get_state (assign, rhs3, !any_pointer_p (rhs3))
             : m_start;
  auto res = sm_ctx->is_zero_assignment (assign) && !unscrubbed_p (rhs1_state)
             && !unscrubbed_p (rhs2_state) && !unscrubbed_p (rhs3_state);
  return res;
}

void
sm_scrub::on_scrubbing_assignment (sm_context *sm_ctx, const supernode *node,
                                   const gassign *assign, tree lhs,
                                   tree reduced_lhs) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);
  auto reduced_state
      = sm_ctx->get_state (assign, reduced_lhs, !any_pointer_p (reduced_lhs));
  if (stack_unscrubbed_p (reduced_state))
    sm_ctx->set_next_state (assign, reduced_lhs, m_scrubbed, NULL_TREE,
                            !any_pointer_p (reduced_lhs));

  if (lhs != reduced_lhs && !any_pointer_p (lhs))
    {
      auto lhs_reg
          = sm_ctx->get_old_region_model ()->get_lvalue (lhs, nullptr);
      auto lhs_state = sm_ctx->get_state (assign, lhs_reg);
      if (stack_unscrubbed_p (lhs_state))
        sm_ctx->set_next_state (assign, lhs_reg, m_scrubbed, NULL_TREE);
    }
}

tristate
sm_scrub::is_null (const sm_context *sm_ctx, const svalue *ptr) const
{
  logger *logger = get_logger ();
  LOG_SCOPE (logger);
  gcc_assert (any_pointer_p (ptr));
  auto zero = sm_ctx->get_new_program_state ()
                  ->m_region_model->get_manager ()
                  ->get_or_create_int_cst (ptr->get_type (), 0);
  auto is_null
      = sm_ctx->get_new_program_state ()->m_region_model->eval_condition (
          ptr, EQ_EXPR, zero);
  if (logger)
    logger->log ("is_null.is_known(): %s | is_null.is_true(): %s",
                 is_null.is_known () ? "true" : "false",
                 is_null.is_true () ? "true" : "false");
  return is_null;
}

/* This method tries to determine if we are currently in an inlined function.
    If so, return the inline FUNCTION_DECL, NULL otherwise. */
tree UNUSED
sm_scrub::inside_inlined_scrubber_fn (sm_context *sm_ctx,
                                      const gimple *stmt) const
{
  auto logger = get_logger ();
  LOG_SCOPE (logger);
  if (stmt)
    {
      location_t loc = gimple_location (stmt);
      for (inlining_iterator iter (loc); !iter.done_p (); iter.next ())
        {
          if (tree fn_decl = iter.get_fndecl ())
            {
              if (logger)
                {
                  logger->start_log_line ();
                  logger->log_partial ("fn_decl for current block: ");
                  dump_quoted_tree (logger->get_printer (), fn_decl);
                  logger->end_log_line ();
                }
              if (cfun && fn_decl != cfun->decl)
                {
                  if (DECL_NAME (fn_decl))
                    if (const char *inlined_fn_name
                        = IDENTIFIER_POINTER (DECL_NAME (fn_decl)))
                      if (scrubbers.contains (inlined_fn_name))
                        {
                          if (logger)
                            logger->log ("Found inlined scrubber: %s",
                                         inlined_fn_name);
                          auto cg_node = cgraph_node::get (fn_decl);
                          if (logger)
                            {
                              if (cg_node)
                                cg_node->dump (logger->get_file ());
                              else
                                logger->log ("cg_node == nullptr");
                            }
                        }

                  dump_scrubber (logger);
                  return fn_decl;
                }
            }
        }
    }
  return NULL_TREE;
}

} // end anonymous namespace

std::unique_ptr<state_machine>
make_scrub_state_machine (logger *logger)
{
  return std::make_unique<sm_scrub> (logger);
}

} // end namespace ana