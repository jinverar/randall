/*
 * Native in-process harness — libFuzzer ABI for Randall harness-worker.
 * Soft rejects return 0; intentional bugs abort and kill the worker.
 */
#include "png_parse.h"

#if defined(_WIN32) || defined(__CYGWIN__)
#define PNG_DEMO_EXPORT __declspec(dllexport)
#else
#define PNG_DEMO_EXPORT __attribute__((visibility("default")))
#endif

PNG_DEMO_EXPORT int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)png_parse(data, size);
    return 0;
}
