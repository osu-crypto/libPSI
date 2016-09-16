
#ifndef ZZN_H
#define ZZN_H
#include "miracl_gmt/include/miracl.h"



#define MR_INIT_ZZN fn=mirvar(0);
#define MR_CLONE_ZZN(x) copy(x,fn);
#define MR_ZERO_ZZN zero(fn);

class ZZn 
{ 
    big fn;
#ifdef ZZNS
    mr_small a[UZZNS];
    bigtype b;
#endif

/*
#ifdef ZZNS
    char mem[mr_big_reserve(1,ZZNS)];
#else
    char *mem;
#endif
*/

public:
    ZZn()               {MR_INIT_ZZN MR_ZERO_ZZN} 
    ZZn(int i)          {MR_INIT_ZZN if (i==0) MR_ZERO_ZZN else {convert(i,fn); nres(fn,fn);} }
    ZZn(const Big& c)   {MR_INIT_ZZN nres(c.getbig(),fn); }   /* Big -> ZZn */
    ZZn(big& c)         {MR_INIT_ZZN MR_CLONE_ZZN(c);}
    ZZn(const ZZn& c)   {MR_INIT_ZZN MR_CLONE_ZZN(c.fn);}
    ZZn(char* s)        {MR_INIT_ZZN cinstr(fn,s); nres(fn,fn);}

    ZZn& operator=(const ZZn& c)    {MR_CLONE_ZZN(c.fn) return *this;}
    ZZn& operator=(big c)           {MR_CLONE_ZZN(c) return *this; }

    ZZn& operator=(int i)  {if (i==0) MR_ZERO_ZZN else {convert(i,fn); nres(fn,fn);} return *this;}
    ZZn& operator=(char* s){cinstr(fn,s); nres(fn,fn); return *this;}


/* Use fast in-line code */

    ZZn& operator++() 
        {nres_modadd(fn,get_mip()->one,fn);return *this;}
    ZZn& operator--() 
        {nres_modsub(fn,get_mip()->one,fn);return *this;}
    ZZn& operator+=(int i) 
        {ZZn inc=i; nres_modadd(fn,inc.fn,fn);return *this;}
    ZZn& operator-=(int i) 
        {ZZn dec=i; nres_modsub(fn,dec.fn,fn); return *this;}
    ZZn& operator+=(const ZZn& b) 
        {nres_modadd(fn,b.fn,fn); return *this;}
    ZZn& operator-=(const ZZn& b) 
        {nres_modsub(fn,b.fn,fn); return *this;}
    ZZn& operator*=(const ZZn& b) 
        {nres_modmult(fn,b.fn,fn); return *this;}
    ZZn& operator*=(int i) 
        {nres_premult(fn,i,fn); return *this;}

    ZZn& negate()
        {nres_negate(fn,fn); return *this;}

    BOOL iszero() const;

    operator Big() {Big c; redc(fn,c.getbig()); return c;}   /* ZZn -> Big */
    friend big getbig(ZZn& z) {return z.fn;}

    ZZn& operator/=(const ZZn& b) {nres_moddiv(fn,b.fn,fn); return *this;}
    ZZn& operator/=(int);

    friend ZZn operator-(const ZZn&);
    friend ZZn operator+(const ZZn&,int);
    friend ZZn operator+(int, const ZZn&);
    friend ZZn operator+(const ZZn&, const ZZn&);

    friend ZZn operator-(const ZZn&, int);
    friend ZZn operator-(int, const ZZn&);
    friend ZZn operator-(const ZZn&, const ZZn&);

    friend ZZn operator*(const ZZn&,int);
    friend ZZn operator*(int, const ZZn&);
    friend ZZn operator*(const ZZn&, const ZZn&);

    friend ZZn operator/(const ZZn&, int);
    friend ZZn operator/(int, const ZZn&);
    friend ZZn operator/(const ZZn&, const ZZn&);

    friend BOOL operator==(const ZZn& b1,const ZZn& b2)
    { if (mr_compare(b1.fn,b2.fn)==0) return TRUE; else return FALSE;}
    friend BOOL operator!=(const ZZn& b1,const ZZn& b2)
    { if (mr_compare(b1.fn,b2.fn)!=0) return TRUE; else return FALSE;}

    friend ZZn  one(void);
    friend ZZn  pow( const ZZn&, const Big&);
    friend ZZn  pow( const ZZn&,int);
    friend ZZn  powl(const ZZn&, const Big&);
    friend ZZn  pow( const ZZn&, const Big&, const ZZn&, const Big&);
    friend ZZn  pow( int,ZZn *,Big *);    
	friend int  jacobi(const ZZn&);
#ifndef MR_NO_RAND
    friend ZZn  randn(void);      // random number < modulus
#endif
    friend BOOL qr(const ZZn&);   // test for quadratic residue
    friend BOOL qnr(const ZZn&);  // test for quadratic non-residue
    friend ZZn getA(void);        // get A parameter of elliptic curve
    friend ZZn getB(void);        // get B parameter of elliptic curve

    friend ZZn  sqrt(const ZZn&); // only works if modulus is prime
    friend ZZn  luc( const ZZn&, const Big&, ZZn* b3=NULL);

    big getzzn(void) const;

#ifndef MR_NO_STANDARD_IO
    friend ostream& operator<<(ostream&,const ZZn&);
#endif


    ~ZZn() 
    {
     // MR_ZERO_ZZN  // slower but safer
#ifndef ZZNS  
        mr_free(fn); 
#endif
    }
};
#ifndef MR_NO_RAND
extern ZZn randn(void);  
#endif
extern ZZn getA(void);  
extern ZZn getB(void);    
extern ZZn one(void);

#endif

