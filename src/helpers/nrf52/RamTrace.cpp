#include "RamTrace.h"
#if defined(NRF52_PLATFORM) && defined(RAM_TRACE)
namespace RamTrace { char buf[4096]; volatile int len = 0; }
#endif
