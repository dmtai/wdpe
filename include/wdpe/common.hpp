/**
 * @file common.hpp
 */

#ifdef WDPE_COMPILED_LIB
#undef WDPE_HEADER_ONLY
#if defined(WDPE_SHARED_LIB)
#if defined(_WIN32)
#ifdef wdpe_EXPORTS
#define WDPE_API __declspec(dllexport)
#else
#define WDPE_API __declspec(dllimport)
#endif
#else
#define WDPE_API __attribute__((visibility("default")))
#endif
#else
#define WDPE_API
#endif
#define WDPE_INLINE
#else
#define WDPE_API
#define WDPE_HEADER_ONLY
#define WDPE_INLINE inline
#endif