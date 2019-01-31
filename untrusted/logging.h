#ifndef __Logging_h
#define __Logging_h

#include <pthread.h>
#define __THREAD__ (unsigned int)pthread_self()

#define Ocall_printf(fmt, ...) \
  do { fprintf(stderr, "Thread %u, " fmt, \
                             __THREAD__, ##__VA_ARGS__); } while (0)

#ifndef Debug_off
#define Debug_on 1
#else
#define Debug_on 0
#endif

#define Debug(fmt, ...) \
  do { if (Debug_on) fprintf(stderr, "Thread %u, non-enclave, debug, %s: %d, %s(): " fmt, \
                             __THREAD__, __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)


#ifndef Warning_off
#define Warning_on 1
#else
#define Warning_on 0
#endif

#define Warn(fmt, ...) \
  do { if (Warning_on) fprintf(stderr, "Thread %u, non-enclave, warning, %s: %d, %s(): " fmt, \
                             __THREAD__, __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)


#ifndef Error_off
#define Error_on 0
#else
#define Error_on 1
#endif

#define Error(fmt, ...) \
  do { if (Error_on) fprintf(stderr, "Thread %u, non-enclave, error, %s: %d, %s(): " fmt, \
                             __THREAD__, __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)


#endif
