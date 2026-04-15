#ifndef _ATTRIBUTE_H
#define _ATTRIBUTE_H

#include <gcc-plugin.h>
#include <tree.h>
#include <analyzer/analyzer.h>
#include <analyzer/analyzer-logging.h>

extern const char *SCRUBBER_STR;
extern const char *TO_SCRUB_STR;

tree empty_attribute_handler (tree *, tree, tree, int, bool *);

tree scrubber_attr_handler (tree *, tree, tree, int, bool *);

const struct attribute_spec attributes[] = {
  { SCRUBBER_STR,
    /* The minimum length of the list of arguments of the attribute.  */
    0,
    /* The maximum length of the list of arguments of the attribute
       (-1 for no maximum).  It can also be -2 for fake attributes
       created for the sake of -Wno-attributes; in that case, we
       should skip the balanced token sequence when parsing the attribute.  */
    -1,
    /* Whether this attribute requires a DECL.  If it does, it will be passed
       from types of DECLs, function return types and array element types to
       the DECLs, function types and array types respectively; but when
       applied to a type in any other circumstances, it will be ignored with
       a warning.  (If greater control is desired for a given attribute,
       this should be false, and the flags argument to the handler may be
       used to gain greater control in that case.)  */
    true,
    /* Whether this attribute requires a type.  If it does, it will be passed
       from a DECL to the type of that DECL.  */
    false,
    /* Whether this attribute requires a function (or method) type.  If it
       does, it will be passed from a function pointer type to the target type,
       and from a function return type (which is not itself a function
       pointer type) to the function type.  */
    false,
    /* Specifies if attribute affects type's identity.  */
    false,
    /* Function to handle this attribute.  NODE points to the node to which
       the attribute is to be applied.  If a DECL, it should be modified in
       place; if a TYPE, a copy should be created.  NAME is the canonicalized
       name of the attribute i.e. without any leading or trailing underscores.
       ARGS is the TREE_LIST of the arguments (which may be NULL).  FLAGS gives
       further information about the context of the attribute.  Afterwards, the
       attributes will be added to the DECL_ATTRIBUTES or TYPE_ATTRIBUTES, as
       appropriate, unless *NO_ADD_ATTRS is set to true (which should be done
       on error, as well as in any other cases when the attributes should not
       be added to the DECL or TYPE).  Depending on FLAGS, any attributes to be
       applied to another type or DECL later may be returned;
       otherwise the return value should be NULL_TREE.  This pointer may be
       NULL if no special handling is required beyond the checks implied
       by the rest of this structure.  */
    scrubber_attr_handler,

    /* An array of attribute exclusions describing names of other attributes
       that this attribute is mutually exclusive with.  */
    nullptr },
  { TO_SCRUB_STR, 0, -1, true, false, false, false, empty_attribute_handler,
    nullptr },
  { nullptr, 0, -1, true, false, true, false, empty_attribute_handler,
    nullptr },
};

#endif // _ATTRIBUTE_H