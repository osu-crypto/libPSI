// sketch.cpp
//
// C++ code by Kevin Harmon and Leonid Reyzin
//
// Finds the PinSketch (BCH-based secure sketch) of an input set.
//
// See pinsketch.txt for detailed documentation
// This code and explanatory notes
// are hosted at http://www.cs.bu.edu/~reyzin/code/fuzzy.html

//

#include "pinsketch.h"
//
//int main(int argc, char** argv)
//{
//	long d; // minimum distance of the code;
//		// can handle set difference up to t=(d-1)/2 elements
//		// sketch is (d-1)/2 elements long
//
//    long m; // elements of the set and of the sketch are m-bit values
//
//	int len;// length of argv[1] if it exists
//
//
//	if (argc != 2 || (len=strlen(argv[1]))<5 || strcmp(&argv[1][len-4], ".set"))
//	{
//		cerr << "Usage: sketch A.set" << endl;
//		if (argc == 2)
//			cerr << "(file must be named `*.set`)" << endl;
//		return -1;
//	}
//
//// Fix field and error-tolerance
//	ifstream infile(argv[1]);
//        if (!infile) {
//          cerr << "Could not open file for reading!\n";
//          return -1;
//        }
//	ReadSetParams(m, d, infile);
//
//        GF2X irrP;
//	BuildSparseIrred(irrP, m); // fix irreducible poly of deg m over GF(2)
//	GF2E::init(irrP); // fix field as GF(2^m)
//
//// read in set  
//	vec_GF2E set, ss;
//	ReadSet(set, infile, m);
//	infile.close();
//
//// compute secure sketch of the set
//	BCHSyndromeCompute(ss, set, d);
//
//// write the sketch to file with same name and .ss extension
//	strcpy(&argv[1][strlen(argv[1])-4], ".ss");
//	ofstream outfile (argv[1], ios::out | ios::trunc);
//        if (!outfile) {
//          cerr << "Could not open file for writing!\n";
//          return -1;
//        }
//	OutputSS(outfile, ss, d, GF2E::modulus());
//	outfile.close();
//
//	cout << "Secure sketch written to file `" << argv[1] << "`." << endl;
//	
//	return 0;
//}
