
#ifndef NTL_config__H
#define NTL_config__H

/*************************************************************************

                          NTL Configuration File
                          ----------------------

This file may be modified prior to building NTL so as to specify
some basic configuration options, and to customize
how code is generated so as to improve performance.

The Basic Configuration Options must be set by hand.  If you use the
configuration wizard, then these flags should be set before
the installation process begins;  there values will be retained
by the wizard.

The Performance Options can be set either by hand, by editing this 
file, or (on most Unix platforms) can be set automatically using
the configuration wizard which runs when NTL is installed.

All NTL header files include this file.
By setting these flags here, instead of on the compiler command line,
it is easier to guarantee that NTL library and client code use
consistent settings.  


                                How to do it
                                ------------

To set a flag, just replace the pre-processor directive 
'if 0' by 'if 1' for that flag, which causes the appropriate macro 
to be defined.  Of course,  to unset a flag, just replace the 
'if 1' by an 'if 0'.

You can also do this more conveniently via the command line
using the configure script.


 *************************************************************************/



/*************************************************************************
 *
 * Basic Configuration Options
 *
 *************************************************************************/


 /* None of these flags are set by the configuration wizard;
  * they must be set by hand, before installation begins.
  */


#if 0
#define NTL_LEGACY_NO_NAMESPACE

/* 
 * By default, NTL components are declared inside the namespace NTL.
 * Set this flag if you want to instead have these components
 * declared in the global namespace.  This is for backward
 * compatibility only -- not recommended.
 *
 * To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif


#if 0
#define NTL_LEGACY_INPUT_ERROR

/*
 * Also for backward compatibility.  Set if you want input 
 * operations to abort on error, instead of just setting the
 * "fail bit" of the input stream.
 *
 * To re-build after changing this flag: rm *.o; make ntl.a
 */


#endif

#if 0
#define NTL_DISABLE_TLS_HACK

/* Set if you want to compile NTL without "TLS hack"
 *
 * To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif

#if 0
#define NTL_ENABLE_TLS_HACK

/* Set if you want to compile NTL with "TLS hack"
 *
 * To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif

#if 1
#define NTL_THREADS

/* Set if you want to compile NTL as a thread-safe library.
 *
 * To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif


#if 1
#define NTL_EXCEPTIONS

/* Set if you want to compile NTL with exceptions enabled
 *
 * To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif

#if 0
#define NTL_THREAD_BOOST

/* Set if you want to compile NTL to exploit threads internally.
 *
 * To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif
#

#if 0
#define NTL_GMP_LIP

/* 
 * Use this flag if you want to use GMP as the long integer package.
 * This can result in significantly faster code on some platforms.
 * It requires that the GMP package (version >= 3.1) has already been
 * installed.  You will also have to set the variables GMP_OPT_INCDIR,
 * GMP_OPT_LIBDIR, GMP_OPT_LIB in the makefile (these are set automatically
 * by the confiuration script when you pass the flag NTL_GMP_LIP=on
 * to that script.
 *
 * Beware that setting this flag can break some very old NTL codes.
 *
 * To re-build after changing this flag:
 *   rm *.o; make setup3; make ntl.a
 * You may also have to edit the makefile to modify the variables
 * GMP_OPT_INCDIR, GMP_OPT_LIBDIR, and GMP_OPT_LIB.
 */

#endif

#if 1
#define NTL_GF2X_LIB

/* 
 * Use this flag if you want to use the gf2x library for
 * faster GF2X arithmetic.
 * This can result in significantly faster code, especially
 * when working with polynomials of huge degree.
 * You will also have to set the variables GF2X_OPT_INCDIR,
 * GF2X_OPT_LIBDIR, GF2X_OPT_LIB in the makefile (these are set automatically
 * by the confiuration script when you pass the flag NTL_GF2X_LIB=on
 * to that script.
 *
 * To re-build after changing this flag:
 *   rm GF2X.o; GF2X1.o; make ntl.a
 * You may also have to edit the makefile to modify the variables
 * GF2X_OPT_INCDIR, GF2X_OPT_LIBDIR, and GF2X_OPT_LIB.
 */

#endif


#if 0
#define NTL_LONG_LONG_TYPE long long

/*
 *   If you set the flag NTL_LONG_LONG, then the value of
 *   NTL_LONG_LONG_TYPE will be used
 *   to declare 'double word' signed integer types.
 *   Irrelevant when NTL_GMP_LIP is set.
 *   If left undefined, some "ifdef magic" will attempt
 *   to find the best choice for your platform, depending
 *   on the compiler and wordsize.  On 32-bit machines,
 *   this is usually 'long long'.
 *
 *   To re-build after changing this flag: rm lip.o; make ntl.a
 */

#endif


#if 0
#define NTL_UNSIGNED_LONG_LONG_TYPE unsigned long long

/*
 *   If you set the flag NTL_SPMM_ULL, then the value of
 *   NTL_UNSIGNED_LONG_LONG_TYPE will be used
 *   to declare 'double word' unsigned integer types.
 *   If left undefined, some "ifdef magic" will attempt
 *   to find the best choice for your platform, depending
 *   on the compiler and wordsize.  On 32-bit machines,
 *   this is usually 'unsigned long long'.
 *
 *   To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif


#if 0
#define NTL_CLEAN_INT

/*
 *   This will disallow the use of some non-standard integer arithmetic
 *   that may improve performance somewhat.
 *
 *   To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif

#if 0
#define NTL_CLEAN_PTR

/*
 *   This will disallow the use of some non-standard pointer arithmetic
 *   that may improve performance somewhat.
 *
 *   To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif

 
#if 0
#define NTL_RANGE_CHECK

/*
 *   This will generate vector subscript range-check code.
 *   Useful for debugging, but it slows things down of course.
 *
 *   To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif





#if 0
#define NTL_NO_INIT_TRANS

/*
 *   Without this flag, NTL uses a special code sequence to avoid
 *   copying large objects in return statements.  However, if your
 *   compiler optimizes away the return of a *named* local object,
 *   this is not necessary, and setting this flag will result
 *   in *slightly* more compact and efficient code.  Although
 *   the emeriging C++ standard allows compilers to perform
 *   this optimization, I know of none that currently do.
 *   Most will avoid copying *temporary* objects in return statements,
 *   and NTL's default code sequence exploits this fact.
 *
 *   To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif


#if 0
#define NTL_X86_FIX

/*
 *  Forces the "x86 floating point fix", overriding the default behavior.
 *  By default, NTL will apply the "fix" if it looks like it is
 *  necessary, and if knows how to fix it.
 *  The problem addressed here is that x86 processors sometimes
 *  run in a mode where FP registers have more precision than doubles.
 *  This will cause code in quad_float.c some trouble.
 *  NTL can normally correctly detect the problem, and fix it,
 *  so you shouldn't need to worry about this or the next flag.

 *  To re-build after changing this flag: rm quad_float.o; make ntl.a
 *  
 */

#elif 0
#define NTL_NO_X86_FIX
/*
 *  Forces no "x86 floating point fix", overriding the default behavior.

 *  To re-build after changing this flag: rm quad_float.o; make ntl.a
 */

#endif



#if 0
#define NTL_LEGACY_SP_MULMOD

/* Forces legacy single-precision MulMod implementation.
 */

#endif


#if 0
#define NTL_DISABLE_LONGDOUBLE

/* Explicitly disables us of long double arithmetic
 */

#endif


#if 0
#define NTL_DISABLE_LONGLONG

/* Explicitly disables us of long long arithmetic 
 */

#endif

#if 0
#define NTL_DISABLE_LL_ASM

/* Explicitly disables us of inline assembly as a replacement
 * for long lobg arithmetic.
 */

#endif


#if 0
#define NTL_MAXIMIZE_SP_NBITS

/* Allows for 62-bit single-precision moduli on 64-bit platforms.
 * By default, such moduli are restricted to 60 bits, which
 * usually gives slightly better performance across a range of
 * of parameters.
 */

#endif

/*************************************************************************
 *
 *  Performance Options
 *
 *************************************************************************/


/* One can choose one of three different stragtegies for long integer
 * arithmetic: the default, NTL_LONG_LONG, or NTL_AVOID_FLOAT.
 * The configuration wizard will choose among them.
 * 
 */

#if 1
#define NTL_LONG_LONG

/*
 *
 *   For platforms that support it, this flag can be set to cause
 *   the low-level multiplication code to use the type "long long",
 *   which may yield a significant performance gain,
 *   but on others, it can yield no improvement and can even
 *   slow things down.
 *
 *
 *   See below (NTL_LONG_LONG_TYPE) for how to use a type name 
 *   other than "long long".
 *
 *   If you set NTL_LONG_LONG, you might also want to set
 *   the flag NTL_TBL_REM (see below).
 *
 *   To re-build after changing this flag:  rm lip.o; make ntl.a
 */

#elif 0
#define NTL_AVOID_FLOAT

/*
 *
 *   On machines with slow floating point or---more comminly---slow int/float
 *   conversions, this flag can lead to faster code.
 *
 *   If you set NTL_AVOID_FLOAT, you should probably also
 *   set NTL_TBL_REM (see below).
 *
 *   To re-build after changing this flag:  rm lip.o; make ntl.a
 */

#endif


/* There are three strategies to implmement single-precision
 * modular multiplication with precondinition (see the MulModPrecon
 * function in the ZZ module): the default, and NTL_SPMM_ULL,
 * and NTL_SPMM_ASM.
 * This plays a crucial role in the  "small prime FFT" used to 
 * implement polynomial arithmetic, and in other CRT-based methods 
 * (such as linear  algebra over ZZ), as well as polynomial and matrix 
 * arithmetic over zz_p.  
 */



#if 0
#define NTL_SPMM_ULL

/*    This also causes an "all integer"
 *    implementation of MulModPrecon to be used.
 *    It us usually a faster implementation,
 *    but it is not enturely portable.
 *    It relies on double-word unsigned multiplication
 *    (see NTL_UNSIGNED_LONG_LONG_TYPE above). 
 *
 *    To re-build after changing this flag: rm *.o; make ntl.a
 */

#elif 0
#define NTL_SPMM_ASM

/*    Like this previous flag, this also causes an "all integer"
 *    implementation of MulModPrecon to be used.
 *    It relies assembler code to do double-word unsigned multiplication.
 *    This is only supported on a select mechines under GCC. 
 *
 *    To re-build after changing this flag: rm *.o; make ntl.a
 */


#endif



/*
 * The following two flags provide additional control for how the 
 * FFT modulo single-precision primes is implemented.
 */

#if 0
#define NTL_FFT_BIGTAB

/*
 * Precomputed tables are used to store all the roots of unity
 * used in FFT computations. 
 *
 *   To re-build after changing this flag: rm *.o; make ntl.a
 */


#endif


#if 0
#define  NTL_FFT_LAZYMUL

/*
 * This flag only has an effect when combined with 
 * either the NTL_SPMM_ULL or NTL_SPMM_ASM flags. 
 * When set, a "lazy multiplication" strategy due to David Harvey:
 * see his paper "FASTER ARITHMETIC FOR NUMBER-THEORETIC TRANSFORMS".
 *
 *   To re-build after changing this flag: rm *.o; make ntl.a
 */


#endif





/* The next six flags NTL_AVOID_BRANCHING, NTL_TBL_REM, NTL_TBL_REM_LL,
 * NTL_GF2X_ALTCODE, NTL_GF2X_ALTCODE1, and NTL_GF2X_NOINLINE
 * are also set by the configuration wizard.  
 */



#if 0
#define NTL_AVOID_BRANCHING

/*
 *   With this option, branches are replaced at several 
 *   key points with equivalent code using shifts and masks.
 *   It may speed things up on machines with 
 *   deep pipelines and high branch penalities.
 *   This flag mainly affects the implementation of the
 *   single-precision modular arithmetic routines.
 *
 *   To re-build after changing this flag: rm *.o; make ntl.a
 */

#endif



#if 0
#define NTL_TBL_REM

/*
 *
 *   With this flag, some divisions are avoided in the
 *   ZZ_pX multiplication routines.  If you use the NTL_AVOID_FLOAT 
 *   or NTL_LONG_LONG flags, then you should probably use this one too.
 *
 *   To re-build after changing this flag: 
 *      rm lip.o; make ntl.a
 */

#endif


#if 0
#define NTL_TBL_REM_LL

/*
 *
 *   This forces the LONG_LONG version if TBL_REM
 *
 *   Irrelevent when NTL_GMP_LIP is set.
 *
 *   To re-build after changing this flag: 
 *      rm lip.o; make ntl.a
 */

#endif


#if 0
#define NTL_CRT_ALTCODE

/*
 * Employs an alternative CRT strategy.
 * Only relevant with GMP.
 * Seems to be marginally faster on some x86_64 platforms.
 *
 *   To re-build after changing this flag: 
 *      rm lip.o; make ntl.a
 */

#endif

#if 0
#define NTL_CRT_ALTCODE_SMALL

/*
 * Employs an alternative CRT strategy for small moduli.
 * Only relevant with GMP.
 * Seems to be marginally faster on some x86_64 platforms.
 *
 *   To re-build after changing this flag: 
 *      rm lip.o; make ntl.a
 */

#endif


#if 0
#define NTL_GF2X_ALTCODE

/*
 * With this option, the default strategy for implmenting low-level
 * GF2X multiplication is replaced with an alternative strategy.
 * This alternative strategy seems to work better on RISC machines
 * with deep pipelines and high branch penalties (like a powerpc),
 * but does no better (or even worse) on x86s.
 *
 * To re-build after changing this flag: rm GF2X.o; make ntl.a
 */

#elif 0
#define NTL_GF2X_ALTCODE1


/*
 * Yest another alternative strategy for implementing GF2X
 * multiplication.
 *
 * To re-build after changing this flag: rm GF2X.o; make ntl.a
 */


#endif

#if 0
#define NTL_GF2X_NOINLINE

/*
 * By default, the low-level GF2X multiplication routine in inlined.
 * This can potentially lead to some trouble on some platforms,
 * and you can override the default by setting this flag.
 *
 * To re-build after changing this flag: rm GF2X.o; make ntl.a
 */

#endif


#if 0
#define NTL_PCLMUL

/* 
 * Use this flag for faster GF2X arithmetc.  
 * This enables the use of the PCLMUL instruction on x86-64
 * machines. 
 *
 * To re-build after changing this flag:
 *   rm GF2X.o; make ntl.a
 */

#endif






#endif
