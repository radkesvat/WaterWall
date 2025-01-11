#ifndef WW_EXPORT_H_
#define WW_EXPORT_H_

// WW_EXPORT
#if defined(WW_STATICLIB) || defined(WW_SOURCE)
    #define WW_EXPORT
#elif defined(_MSC_VER)
    #if defined(WW_DYNAMICLIB) || defined(WW_EXPORTS) || defined(hv_EXPORTS)
        #define WW_EXPORT  __declspec(dllexport)
    #else
        #define WW_EXPORT  __declspec(dllimport)
    #endif
#elif defined(__GNUC__)
    #define WW_EXPORT  __attribute__((visibility("default")))
#else
    #define WW_EXPORT
#endif

// WW_INLINE
#define WW_INLINE static inline

// WW_DEPRECATED
#if defined(WW_NO_DEPRECATED)
#define WW_DEPRECATED
#elif defined(__GNUC__) || defined(__clang__)
#define WW_DEPRECATED   __attribute__((deprecated))
#elif defined(_MSC_VER)
#define WW_DEPRECATED   __declspec(deprecated)
#else
#define WW_DEPRECATED
#endif

// WW_UNUSED
#if defined(__GNUC__)
    #define WW_UNUSED   __attribute__((visibility("unused")))
#else
    #define WW_UNUSED
#endif

// @param[IN | OUT | INOUT]
#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif

// @field[OPTIONAL | REQUIRED | REPEATED]
#ifndef OPTIONAL
#define OPTIONAL
#endif

#ifndef REQUIRED
#define REQUIRED
#endif

#ifndef REPEATED
#define REPEATED
#endif

#ifdef __cplusplus

#ifndef EXTERN_C
#define EXTERN_C            extern "C"
#endif

#ifndef BEGIN_EXTERN_C
#define BEGIN_EXTERN_C      extern "C" {
#endif

#ifndef END_EXTERN_C
#define END_EXTERN_C        } // extern "C"
#endif

#ifndef BEGIN_NAMESPACE
#define BEGIN_NAMESPACE(ns) namespace ns {
#endif

#ifndef END_NAMESPACE
#define END_NAMESPACE(ns)   } // namespace ns
#endif

#ifndef USING_NAMESPACE
#define USING_NAMESPACE(ns) using namespace ns;
#endif

#ifndef DEFAULT
#define DEFAULT(x)  = x
#endif

#ifndef ENUM
#define ENUM(e)     enum e
#endif

#ifndef STRUCT
#define STRUCT(s)   struct s
#endif

#else

#define EXTERN_C    extern
#define BEGIN_EXTERN_C
#define END_EXTERN_C

#define BEGIN_NAMESPACE(ns)
#define END_NAMESPACE(ns)
#define USING_NAMESPACE(ns)

#ifndef DEFAULT
#define DEFAULT(x)
#endif

#ifndef ENUM
#define ENUM(e)\
typedef enum e e;\
enum e
#endif

#ifndef STRUCT
#define STRUCT(s)\
typedef struct s s;\
struct s
#endif

#endif // __cplusplus

#define BEGIN_NAMESPACE_HV  BEGIN_NAMESPACE(hv)
#define END_NAMESPACE_HV    END_NAMESPACE(hv)
#define USING_NAMESPACE_HV  USING_NAMESPACE(hv)

// MSVC ports
#ifdef _MSC_VER

#pragma warning (disable: 4251) // STL dll
#pragma warning (disable: 4275) // dll-interface

#if _MSC_VER < 1900 // < VS2015

#ifndef __cplusplus
#ifndef inline
#define inline __inline
#endif
#endif

#ifndef snprintf
#define snprintf _snprintf
#endif

#endif
#endif

#endif // WW_EXPORT_H_
