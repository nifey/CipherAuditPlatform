// BEGIN GCC RELATED INCLUDE
#include <gcc-plugin.h>
#include <diagnostic.h>
#include <intl.h>
#include <plugin-version.h>
#include <tree-pass.h>
#include <tree.h>

#include <iostream>
#include <memory>
#include <string.h>

#include <analyzer/analyzer.h>
#include <analyzer/analyzer-logging.h>
// END GCC RELATED INCLUDE

#include "attribute.h"
#include "sm_scrub.h"

#define UNUSED __attribute__ ((__unused__))

using namespace ana;

int plugin_is_GPL_compatible;

const char *SCRUBBER_STR{ "scrubber" };
const char *TO_SCRUB_STR{ "scrub" };
bool DEBUG{ true };
bool FULL_PROPAGATION{ false };

const struct plugin_info plugin_scrub_info
{
  "0.1", "Nothing to show here for now."
};

void
register_attributes (void *event_data, void *data)
{
  for (const struct attribute_spec *current = attributes; current->name;
       ++current)
    {
      register_attribute (current);
    }
}

void
register_analyzer (void *event_data, void *data)
{
  if (event_data)
    {
      plugin_analyzer_init_iface *iface
          = (plugin_analyzer_init_iface *)event_data;
      LOG_SCOPE (iface->get_logger ());
      iface->register_state_machine (
          make_scrub_state_machine (iface->get_logger ()));
    }
}

static void
build_scrubbers_arg (char *ptr)
{
  char *scrubber;
  while ((scrubber = strsep (&ptr, ",")))
    {
      scrubbers.safe_push (scrubber);
    }
}

int
plugin_init (struct plugin_name_args *plugin_info,
             struct plugin_gcc_version *version)
{
  // Registering plugin information (version and help).
  register_callback (plugin_info->base_name, PLUGIN_INFO, nullptr,
                     (void *)&plugin_scrub_info);
  
  auto plugin_name = plugin_info->base_name;
  printf("Plugin base_name is %s\n", plugin_info->base_name);

  // Looking for arguments
  auto UNUSED target = "main";
  for (auto i = 0; i < plugin_info->argc; i++)
    {
      auto arg = plugin_info->argv[i];
      if (strncmp ("debug", arg.key, 5) == 0)
          DEBUG = true;

      if (strncmp ("target", arg.key, 6) == 0 && arg.value)
          target = arg.value;
          
      if (strncmp ("scrubber", arg.key, 8) == 0 && arg.value)
          build_scrubbers_arg (arg.value);

      if (strncmp("full-propagation", arg.key, 17) == 0)
        FULL_PROPAGATION = true;
    }
  // TODO integrate arguments to the analyzer

  // Registering attributes
  register_callback (plugin_name, PLUGIN_ATTRIBUTES, register_attributes,
                     nullptr);

  // Registering state machine
  register_callback (plugin_name, PLUGIN_ANALYZER_INIT, register_analyzer,
                     nullptr);

  if (strncmp (gcc_version.basever, version->basever,
               strlen (gcc_version.basever)))
    return 1;

  return 0;
}