//#include "BchCode.h"
//
//
//
//// bch.cpp
////
//// C++ code by Kevin Harmon and Leonid Reyzin (reyzin@cs.bu.edu)
//// for sublinear-time syndrome encoding and decoding of
//// binary BCH codes.  See pinsketch.txt for information
//// on using this inside PinSketch, BCH-based secure sketches.
////
//// Uses Victor Shoup's NTL (see http://www.shoup.net)
////
//// Contains two public functions: BCHSyndromeCompute
//// and BCHSyndromeDecode
////
//// See Syndrome Encoding and Decoding of BCH Codes in Sublinear Time
//// (Excerpted from "Fuzzy Extractors:
////    How to Generate Strong Keys from Biometrics and Other Noisy Data,"
////    SIAM Journal on Computing, 38(1):87-139, 2008, 
////    http://arxiv.org/abs/cs/0602007)
//// by Yevgeniy Dodis, Rafail Ostrovsky, Leonid Reyzin and Adam Smith
//// (file bch-excerpt.pdf) for the mathematics behind this.
////
//// This code and explanatory notes are  hosted at
//// http://www.cs.bu.edu/~reyzin/code/fuzzy.html
////
////
//
//#include "pinsketch.h"
//
//
/////////////////////////////////////////////////////////////////////////////
//// PURPOSE:
//// Computes the syndrome of a sparse vector
//// of the binary BCH code of design distance d.
//// The vector is viewed as a vector of 0's and 1's
//// being indexed by all nonzero elements of GF2E; because
//// it is sparse, it is given as the set a of 
//// elements of GF2E where the coordinates of the vector are equal to 1.
//// If used to compute the secure sketch, the sketch will
//// tolerate symmetric difference of up to (d-1)/2
////
////
//// ALGORITHM:
//// The syndrome is computed as a vector of
//// f(j) = (a_0)^j + (a_2)^j + ... + (a_s)^j
//// for odd i from 1 do d-1, where a_i is the i-th component
//// of the input vector A.
//// (only the odd j are needed, because
//// f(2j) is simply the square of f(j)).
//// Because in C++ we number from 0, f(j) will reside
//// in location (j-1)/2.
////
////
//// ASSUMPTIONS:
//// Let m=GF2E::degree() (i.e., the field is GF(2^m)).
//// Assumes d is odd,
//// greater than 1, and less than 2^m (else BCH codes don't make sense).
//// Assumes the input set has no zeros (they will be ignored)
////
//// 
//// RUNNING TIME:
//// Takes time O(len*d) operations in GF(2^m),
//// where len is the length of the input vector
////
//void BCHSyndromeCompute(vec_GF2E & ss, const vec_GF2E & a, long d)
//{
//    GF2E a_i_to_the_j, multiplier;
//    long i, j;
//
//    ss.SetLength((d - 1) / 2); // half the syndrome length, 
//                               // because even power not needed
//
//                               // We will compute the fs in parallel: first add
//                               // all the powers of a_1, then of a_2, ..., then of a_s
//    for (i = 0; i < a.length(); ++i)
//    {
//
//        a_i_to_the_j = a[i];
//        sqr(multiplier, a[i]); // multiplier = a[i]*a[i];
//
//                               // special-case 0, because it doesn't need to be multiplied
//                               // by the multiplier
//        ss[0] += a_i_to_the_j;
//
//        for (long j = 3; j < d; j += 2)
//        {
//            a_i_to_the_j *= multiplier;
//            ss[(j - 1) / 2] += a_i_to_the_j;
//
//        }
//    }
//}
//
//
/////////////////////////////////////////////////////////////////////////////
//// Produces a vector res such that res[2i]=ss[i]
//// and res[2i+1]=ss[i]*ss[i]
////
//// Used to recover the redundant representation
//// of the BCH syndrome (which includes even values of j)
//// from the representation produced by BCHSyndromeCompute
//// Because C++ indexes from 0, the j-th coordinate of the syndrome
//// will end up in location j-1.
////
//// Takes time O(d) operations in GF2E, where d is the output length
////
//static
//void InterpolateEvens(vec_GF2E & res, const vec_GF2E & ss)
//{
//    // uses relation syn(j) = syn(j/2)^2 to recover syn from ss
//    long i;
//
//    res.SetLength(2 * ss.length());
//    // odd coordinates (which, confusingly, means even i)
//    // are just copied from the input
//    for (i = 0; i < ss.length(); ++i)
//        res[2 * i] = ss[i];
//    // even coordinates (odd i) are computed via squaring.
//    for (i = 1; i < res.length(); i += 2)
//        sqr(res[i], res[(i - 1) / 2]); // square
//}
//
//
/////////////////////////////////////////////////////////////////////////////
//// PURPOSE:
//// Returns true if f fully factors into distinct roots
//// (i.e., if f is a product of distinct monic degree-1 polynomials
//// times possibly a constant)
//// and false otherwise.
//// If f is zero, returns false.
////
//// ALGORITHM:
//// Let m=GF2E::degree() (i.e., the field is GF(2^m)).
//// The check is accomplished by checking if f divides X^{2^m} - X, 
//// or equivalently if X^{2^m}-X is 0 mod f. 
//// X^{2^m} - X has 2^m distinct roots -- namely,
//// every element of the field is a root.  Hence, f divides it if and only
//// if f has all its roots and they are all distinct.
////
//// RUNNING TIME:
//// Depends on NTL's implementation of FrobeniusMap, but for inputs of degree
//// e that is relatively small compared m, should take e^{\log_2 3} m
//// operations in GF(2^m).  Note that \log_2 3 is about 1.585.
//static
//bool CheckIfDistinctRoots(const GF2EX & f)
//{
//    if (IsZero(f))
//        return false;
//    // We hanlde degree 0 and degree 1 case separately, so that later
//    // we can assume X mod f is the same as X
//    if (deg(f) == 0 || deg(f) == 1)
//        return true;
//
//    GF2EXModulus F;
//    // F is the same as f, just more efficient modular operations
//    build(F, f);
//
//    GF2EX h;
//    FrobeniusMap(h, F); // h = X^{2^m} mod F
//
//                        // If X^{2^m} - X = 0 mod F, then X^{2^m} mod F
//                        // should be just X (because degree of F > 1)
//    return (IsX(h));
//}
//
//
/////////////////////////////////////////////////////////////////////////////
//// PURPOSE:
//// Given syndrome ssWithoutEvens of BCH code with design distance d,
//// finds sparse vector (with no more than
//// (d-1)/2 ones) with that syndrome
//// (note that syndrome as well sparse vector
//// representation are defined at BCHSyndromeCompute above).
//// 'answer' returns positions of ones in the resulting vector.
//// These positions are elements of GF2E (i.e., we view the vector
//// as a vector whose positions are indexed by elements of GF2E).
//// Returns false if no such vector exists, true otherwise
//// The input syndrome is assumed to not have even powers, i.e., 
//// has (d-1)/2 elements, such as the syndrome computed by BCHSyndromeCompute.
//// 
//// ASSUMPTIONS:
//// Let m=GF2E::degree() (i.e., the field is GF(2^m)).
//// This algorithm assumes that d is odd, greater than 1, and less than 2^m.
//// (else BCH codes don't make sense).
//// Assumes input is of length (d-1)/2. 
////
//// ALGORITHM USED:
//// Implements BCH decoding based on Euclidean algorithm;
//// For the explanation of the algorithm, see
//// Syndrome Encoding and Decoding of BCH Codes in Sublinear Time
//// (Excerpted from Fuzzy Extractors:
////    How to Generate Strong Keys from Biometrics and Other Noisy Data)
//// by Yevgeniy Dodis, Rafail Ostrovsky, Leonid Reyzin and Adam Smith
//// or Theorem 18.7 of Victor Shoup's "A Computational Introduction to 
//// Number Theory and Algebra" (first edition, 2005), or
//// pp. 170-173 of "Introduction to Coding Theory" by Jurgen Bierbrauer.
////
////
//// RUNNING TIME:
//// If the output has e elements (i.e., the length of the output vector
//// is e; note that e <= (d-1)/2), then
//// the running time is O(d^2 + e^2 + e^{\log_2 3} m) operations in GF(2^m),
//// each of which takes time O(m^{\log_2 3}) in NTL.  Note that 
//// \log_2 3 is approximately 1.585.
////
//bool BCHSyndromeDecode(vec_GF2E &answer, const vec_GF2E & ssWithoutEvens, long d)
//{
//    long i;
//    vec_GF2E ss;
//
//
//    // This takes O(d) operation in GF(2^m)
//    InterpolateEvens(ss, ssWithoutEvens);
//
//    GF2EX r1, r2, r3, v1, v2, v3, q, temp;
//    GF2EX *Rold, *Rcur, *Rnew, *Vold, *Vcur, *Vnew, *tempPointer;
//
//    // Use pointers to avoid moving polynomials around
//    // An assignment of polynomials requires copying the coefficient vector;
//    // we will not assign polynomials, but will swap pointers instead
//    Rold = &r1;
//    Rcur = &r2;
//    Rnew = &r3;
//
//    Vold = &v1;
//    Vcur = &v2;
//    Vnew = &v3;
//
//
//    SetCoeff(*Rold, d - 1, 1); // Rold holds z^{d-1}
//
//                               // Rcur=S(z)/z where S is the syndrome poly, Rcur = \sum S_j z^{j-1}
//                               // Note that because we index arrays from 0, S_j is stored in ss[j-1]
//    for (i = 0; i<d - 1; i++)
//        SetCoeff(*Rcur, i, ss[i]);
//
//    // Vold is already 0 -- no need to initialize
//    // Initialize Vcur to 1
//    SetCoeff(*Vcur, 0, 1); // Vcur = 1
//
//                           // Now run Euclid, but stop as soon as degree of Rcur drops below
//                           // (d-1)/2
//                           // This will take O(d^2) operations in GF(2^m)
//
//    long t = (d - 1) / 2;
//
//
//
//    while (deg(*Rcur) >= t) {
//        // Rold = Rcur*q + Rnew
//        DivRem(q, *Rnew, *Rold, *Rcur);
//
//        // Vnew = Vold - qVcur)
//        mul(temp, q, *Vcur);
//        sub(*Vnew, *Vold, temp);
//
//
//        // swap everything
//        tempPointer = Rold;
//        Rold = Rcur;
//        Rcur = Rnew;
//        Rnew = tempPointer;
//
//        tempPointer = Vold;
//        Vold = Vcur;
//        Vcur = Vnew;
//        Vnew = tempPointer;
//    }
//
//
//
//    // At the end of the loop, sigma(z) is Vcur
//    // (up to a constant factor, which doesn't matter,
//    // since we care about roots of sigma).
//    // The roots of sigma(z) are inverses of the points we
//    // are interested in.  
//
//
//    // We will check that 0 is not
//    // a root of Vcur (else its inverse won't exist, and hence
//    // the right polynomial doesn't exist).
//    if (IsZero(ConstTerm(*Vcur)))
//        return false;
//
//    // Need sigma to be monic for FindRoots
//    MakeMonic(*Vcur);
//
//    // check if sigma(z) has distinct roots if not, return false
//    // this will take O(e^{\log_2 3} m) operations in GF(2^m),
//    // where e is the degree of sigma(z)
//    if (CheckIfDistinctRoots(*Vcur) == false)
//        return false;
//
//    // find roots of sigma(z)
//    // this will take O(e^2 + e^{\log_2 3} m) operations in GF(2^m),
//    // where e is the degree of sigma(z)
//    answer = FindRoots(*Vcur);
//
//    // take inverses of roots of sigma(z)
//    for (i = 0; i < answer.length(); ++i)
//        answer[i] = inv(answer[i]);
//
//
//    // It is now necessary to verify if the resulting vector
//    // has the correct syndrome: it is possible that it does
//    // not even though the polynomial sigma(z) factors
//    // completely
//    // This takes O(de) operations in GF(2^m)
//    vec_GF2E test;
//    BCHSyndromeCompute(test, answer, d);
//
//    return (test == ssWithoutEvens);
//}
//
