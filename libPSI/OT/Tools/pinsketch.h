#ifndef __PIN_SKETCH_H
#define __PIN_SKETCH_H

#include <fstream>
#include <NTL/vec_ZZ.h>
#include <NTL/GF2XFactoring.h>
#include <NTL/GF2EXFactoring.h>

using namespace std; // may be needed to compile on some platforms; may need to be removed on others
NTL_CLIENT

/************************ I/O ************************************/
void ReadSetParams(long &m, long &d, istream &infile);
void ReadSet(vec_GF2E & set, istream &infile, long m);

void ReadSSParams(long &m, long &d, GF2X &irrP, istream &infile) ;
void ReadSS(vec_GF2E & ss, istream &infile, long d);

void OutputSS(ostream &outfile, const vec_GF2E & syn, long d, const GF2X & irrP);
void OutputSetDifference(ostream &outfile, const vec_GF2E & setDifference);

/************************ BCH Syndrome Encoding/Decoding ***************/
void BCHSyndromeCompute(vec_GF2E &answer, const vec_GF2E & set, long d);
bool BCHSyndromeDecode(vec_GF2E &answer, const vec_GF2E & syndrome, long d);

#endif
