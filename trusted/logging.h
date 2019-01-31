#ifndef __Logging_h
#define __Logging_h


#ifndef Debug_off
#define Debug_on 1
#else
#define Debug_on 0
#endif

#define Debug_enclave(fmt, ...) \
  do { if (Debug_on) printf("enclave, debug, %s: %d, %s(): " fmt, \
                             __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)


#ifndef Warning_off
#define Warning_on 1
#else
#define Warning_on 0
#endif

#define Warn_enclave(fmt, ...) \
  do { if (Debug_on) printf("enclave, warning, %s: %d, %s(): " fmt, \
                             __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)

#ifndef Error_off
#define Error_on 0
#else
#define Error_on 1
#endif

#define Error_enclave(fmt, ...) \
  do { if (Debug_on) printf("enclave, error, %s: %d, %s(): " fmt, \
                             __FILE__, __LINE__, __func__, ##__VA_ARGS__); } while (0)

#endif
