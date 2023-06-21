#include "SimpleDataflowChecker/DataflowSanitizer.hpp"

raw_ostream& operator<<(raw_ostream& os, const DataflowSanitizer& d)
{
  d.print(os);
  return os;
}

