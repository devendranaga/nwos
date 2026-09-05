#ifndef NETOS_COMPILER_DEF_H
#define NETOS_COMPILER_DEF_H

#if defined(__clang__) && __has_attribute(counted_by)
#define __counted_by_ptr(member) __attribute__((counted_by(member)))
#elif defined(__GNUC__) && (__GNUC__ >= 16) && __has_attribute(counted_by)
#define __counted_by_ptr(member) __attribute__((counted_by(member)))
#else
#define __counted_by_ptr(member) /* Drop it for GCC 15 */
#endif

#endif

