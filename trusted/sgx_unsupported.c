#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "Wolfssl_Enclave_t.h"

#define Ocall_buffer_size 65536

int printf(const char *fmt, ...)
{
    char buf[Ocall_buffer_size] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, Ocall_buffer_size, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, Ocall_buffer_size, fmt, ap);
    va_end(ap);
    return ret;
}

int asprintf(char** str, const char* fmt, ...){
  va_list argp;
  va_start(argp,fmt);
  //  char one_char[1];
  //  int len = vsnprintf(one_char, 1, fmt, argp);
  int len = vsnprintf(NULL, 0, fmt, argp);
  if(len<1){
    *str = NULL;
    return len;
  }
  va_end(argp);
  *str = malloc(len+1);
  if(!str){
    return -1;
  }
  va_start(argp, fmt);
  vsnprintf(*str, len+1, fmt, argp);
  va_end(argp);
  return len;
}

int rand(){
  int result;
  sgx_read_rand((unsigned char*)&result, sizeof(int));
  return result;
}
