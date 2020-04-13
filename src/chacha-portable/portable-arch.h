#ifndef __PORTABLE_ARCH_42
#define __PORTABLE_ARCH_42

/*****************************
 * Unaligned access detection
 *****************************/

// based on https://sourceforge.net/p/predef/wiki/Architectures/

// x64
#if defined(__amd64__) || \
        defined(__amd64) || \
        defined(__x86_64__) || \
        defined(__x86_64) || \
        defined(_M_X64) || \
        defined(_M_AMD64) 
#   define __UNALIGNED_ACCESS 1
#endif

// arm
#if (defined(_M_ARM) && _M_ARM == 6) || defined(__ARM_ARCH_6__)
/ special case ARMv6 allowes 32bit access, not higher
#   define __UNALIGNED_32ACCESS 1
#elif (defined(_M_ARM) && _M_ARM == 7) || (defined(__ARM_ARCH_7__) && !defined(__ARM_ARCH_7M__))
// special case, arm7 needs work to avoid certain instructions
#   define __UNALIGNED_ACCESS_ARM7 1
#elif (defined(_M_ARM) && _M_ARM > 7) || \
        defined(_M_ARM64) || \
        defined(__aarch64__) || \
        defined(__ARM_FEATURE_UNALIGNED)
#   define __UNALIGNED_ACCESS 1
#endif

// x86
#if defined(i386) || \
    defined(__i386) || \
    defined(__i386__) || \
    defined(_M_IX86) || \
    defined(__X86__) || \
    defined(_X86_)
#   define __UNALIGNED_ACCESS 1
#endif


/*****************************
 * Little endianness detection
 *****************************/

// based on https://sourceforge.net/p/predef/wiki/Endianness/
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#   define __HAVE_LITTLE_ENDIAN 1
#elif defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || \
        defined(__MIPSEL) || \
        defined(__MIPSEL__)
#   define __HAVE_LITTLE_ENDIAN 1
#endif

#endif
