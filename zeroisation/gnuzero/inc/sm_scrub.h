#ifndef _SM_SCRUB_H
#define _SM_SCRUB_H

#include <memory>

#include <gcc-plugin.h>
#include <tree.h>
#include <analyzer/analyzer.h>
#include <analyzer/analyzer-logging.h>
#include <analyzer/sm.h>

namespace ana
{

std::unique_ptr<state_machine> make_scrub_state_machine (logger *logger);

class scrubber
{
public:
  scrubber (const char *);
  const char *get_name () const;
  bool operator== (const scrubber &) const;

private:
  const char *m_name;
};

extern auto_vec<scrubber> scrubbers;
extern auto_vec<tree> to_scrub;

void dump_scrubber (logger *logger);
void dump_to_scrub (logger *logger);

namespace
{

class sm_scrub;
class data_leak;

} // end anonymous namespace

} // end namespace ana

#endif // _SM_SCRUB_H