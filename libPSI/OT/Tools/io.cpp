// io.cpp
//
// C++ code by Kevin Harmon and Leonid Reyzin
//
// Input/output routines for PinSketch
// (BCH-based secure sketches)
//
// See pinsketch.txt for detailed documentation
// This code and explanatory notes
// are hosted at http://www.cs.bu.edu/~reyzin/code/fuzzy.html
//


#include "pinsketch.h"


/***************** Converting integer to elements of GF(2^e) and back **************************/


// Uses the bits of the polynomial representation of an element of GF2E to come up with
// an integer with the same bits
static 
void BinElemToNum(ZZ & a, const GF2E & e) {
	GF2X g = rep(e); // convert to polynomial
	long numBytes=NumBytes(g);
	unsigned char * buffer = new unsigned char[numBytes];
	BytesFromGF2X(buffer, g, numBytes);
	ZZFromBytes(a, buffer, numBytes);
	delete [] buffer;
}


// Uses binary representation of an integer to come up with an
// element of GF(2^m) by using the bits of the integer
// as bits of a polynomial and then reducing modulo the irreducible polynomial that
// generates the field.
static 
void NumToBinElem(GF2E & e, const ZZ & a, long m) {
        GF2X g;
	long numBytes=NumBytes(a);
	unsigned char * buffer = new unsigned char[numBytes];
	BytesFromZZ(buffer, a, numBytes);
	GF2XFromBytes(g, buffer, numBytes);
	delete [] buffer;
       	conv (e, g); // Convert from polynomial to field element
}



/******************************************** I/O ROUTINES ******************************/

// Reads in a vector of integers from a file, converting them to elements of GF(2^m)
// Designed to read a .set file after the ReadSetParams routine 
void ReadSet(vec_GF2E & set, istream &infile, long m)
{
	vec_ZZ r;

	// Read in the vector of integers
	infile >> r; // uses NTL I/O routine

	// Convert the integers to elements of GF2E
	set.SetLength(r.length());
	for (long j = 0; j < r.length(); j++)
	  NumToBinElem(set[j], r[j], m);
}



// Reads in the field size m and the desired error-tolerance t from
// the input file, where they are assumed to be present in the format
// t=<integer> m=<integer> (no spaces around '=' are allowed)
// Returns m and the minimum distance of the code d=2t+1
void ReadSetParams(long &m, long &d, istream &infile)
{
	long t = 0;  // t = max set diff tolerated
	int count = 2; // # of params to be read in
	char c1, c2;
	ZZ temp;
	
	while (count > 0)
	{
		c1 = '\0';
	  	c2 = '\0';
		while (c2 != '=' && !infile.eof())
			infile >> c1 >> c2;
		count--;
		switch (c1)
		{
			case 't': infile >> t; break;
			case 'm': infile >> m; break;
		}
	}

	if (infile.eof() || t<=0 || m<=0)
	{
		cerr << "Bad input format!" << endl;
		exit(-1);
	}

	d = 2*t+1; // t = max set diff tolerated, d=2*t+1

	return;
}

// Reads in from the input file (presumably one that conains
// a secure sketch output by OutputSS)
// the field size m, the minimum distance d of the code,
// and the irreducible polynomial over GF(2)
// used for represending the field GF(2^m)
void ReadSSParams(long &m, long &d, GF2X &irrP, istream & infile)
{
	infile >> d >> m >> irrP;

	if (infile.eof() || d<=0 || m<=0)
	{
		cerr << "Bad input format!" << endl;
		exit(-1);
	}

	return;
}

// Reads secure sketch from a file.  The secure
// sketch is assumed to be (d-1)/2 values
// in GF(2^m).  Assumes GF(2^m) was already
// constructed via NTL's ConstructField
// If the file was produced using OutputSS, assumes
// ReadSSParams already read the parameters contained
// at the beginning of the file
void ReadSS(vec_GF2E & ss, istream &infile, long d)
{
	ss.SetLength((d-1)/2);
	for (long i = 0; i < (d-1)/2; ++i)
		infile >> ss[i]; // uses NTL I/O routine
}

 
// Outputs the set difference by converting elements of GF2E back
// to the more human-readable integer representation
void OutputSetDifference(ostream &outfile, const vec_GF2E & setDifference)
{
        ZZ a;
	int i;

        outfile << "Set Difference = {\n";
        for (i = 0; i < setDifference.length(); ++i) {
	  BinElemToNum(a, setDifference[i]);
          outfile <<a<<endl; // print output in integer form       
	}
        outfile << "}\n";
	
}

// Output secure sketch into a file: first the distance d
// (tolerated errors are t=2d-1), then the degree m of the field,
// then the (d-1)/2 elements of the secure sketch
void OutputSS(ostream &outfile, const vec_GF2E & ss, long d, const GF2X & irrP)
{
	// record the parameters that were used
	outfile << d << " " << GF2E::degree() << " " << irrP << " " << endl;

	// now record the values themselves
	for (long j = 0; j < (d-1)/2; ++j)
	  outfile << ss[j] << ((j == (d-3)/2) ? "\n" : " ");
}


