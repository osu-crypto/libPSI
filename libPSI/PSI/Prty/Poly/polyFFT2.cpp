#include "libPSI/config.h"
#ifdef ENABLE_PRTY_PSI
#include "polyFFT2.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <vector>
#include <thread>
#include <NTL/BasicThreadPool.h>
#include <omp.h>
namespace osuCrypto
{
#define LEFT(X) (2*X+1)
#define RIGHT(X) (2*X+2)
#define PAPA(X) ((X-1)/2)


	void polyFFT2::init(ZZ &prime, u64 numThreads) {
		mPrime = prime;
		mNumThreads = numThreads;
	}

	void build_tree_1thread(ZZ_pX* tree, ZZ_p* points) {

	}


	void polyFFT2::build_tree(ZZ_pX* tree, ZZ_p* points) {

	}

}
#endif