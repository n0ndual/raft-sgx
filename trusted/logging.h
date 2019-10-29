#ifndef Logging_h
#define Logging_h

#include "sgx_unsupported.h"

#ifndef Debug_off
#define Debug_on 1
#else
#define Debug_on 0
#endif

#define Debug_enclave(fmt, ...) \
  do { if (Debug_on) printf("E, D, %s: %d, %s(): " fmt, \
                             __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)


#ifndef Warning_off
#define Warning_on 1
#else
#define Warning_on 0
#endif

#define Warn_enclave(fmt, ...) \
  do { if (Warning_on) printf("E, W, %s: %d, %s(): " fmt, \
                             __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)

#ifndef Error_off
#define Error_on 1
#else
#define Error_on 0
#endif

#define Error_enclave(fmt, ...) \
  do { if (Error_on) printf("E, E, %s: %d, %s(): " fmt, \
                             __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)

#endif
