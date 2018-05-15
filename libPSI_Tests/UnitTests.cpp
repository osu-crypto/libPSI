#include "cryptoTools/Common/Log.h"
#include <functional>
#include "UnitTests.h"
#include "AknBfPsi_Tests.h"
#include "AknBfPsi_Tests.h"
#include "BinOtPsi_Tests.h"

#include "ShamirSSScheme_Tests.h"
#include "DcwBfPsi_Tests.h"
#include "DktMPsi_Tests.h"
#include "EcdhPsi_Tests.h"
#include "Grr18MPSI_Tests.h"
using namespace osuCrypto;
namespace libPSI_Tests
{

    TestCollection Tests([](TestCollection& t) {


        t.add("Psi_kkrt_EmptySet_Test_Impl           ", Psi_kkrt_EmptySet_Test_Impl);
        t.add("Psi_kkrt_FullSet_Test_Impl            ", Psi_kkrt_FullSet_Test_Impl);
        t.add("Psi_kkrt_SingletonSet_Test_Impl       ", Psi_kkrt_SingletonSet_Test_Impl);

        t.add("EcdhPsi_EmptrySet_Test_Impl           ", EcdhPsi_EmptrySet_Test_Impl);
        t.add("EcdhPsi_FullSet_Test_Impl             ", EcdhPsi_FullSet_Test_Impl);
        t.add("EcdhPsi_SingltonSet_Test_Impl         ", EcdhPsi_SingltonSet_Test_Impl);


        //t.add("DktPsi_EmptrySet_Test_Impl            ", DktMPsi_EmptrySet_Test_Impl);
        //t.add("DktPsi_FullSet_Test_Impl              ", DktMPsi_FullSet_Test_Impl);
        //t.add("DktPsi_SingltonSet_Test_Imp           ", DktMPsi_SingltonSet_Test_Impl);


#ifdef ENABLE_DCW
        t.add("DcwPsi_EmptrySet_Test_Impl            ", DcwBfPsi_EmptrySet_Test_Impl);
        t.add("DcwPsi_FullSet_Test_Impl              ", DcwBfPsi_FullSet_Test_Impl);
        t.add("DcwPsi_SingltonSet_Test_Imp           ", DcwBfPsi_SingltonSet_Test_Impl);

        t.add("ShamirSSScheme_GF2X_Test              ", ShamirSSScheme_Test);
#endif
        t.add("RR16_EmptrySet_Test_Impl              ", AknBfPsi_EmptrySet_Test_Impl);
        t.add("RR16_FullSet_Test_Impl                ", AknBfPsi_FullSet_Test_Impl);
        t.add("RR16_SingltonSet_Test_Impl            ", AknBfPsi_SingltonSet_Test_Impl);

        t.add("CuckooHasher_Test_Impl                ", CuckooHasher_Test_Impl);
        t.add("CuckooHasher_parallel_Test_Impl       ", CuckooHasher_parallel_Test_Impl);

        t.add("Rr17a_Oos_EmptrySet_Test_Impl         ", Rr17a_Oos_EmptrySet_Test_Impl);
        t.add("Rr17a_Oos_SingltonSet_Test_Impl       ", Rr17a_Oos_SingltonSet_Test_Impl);
        t.add("Rr17a_Oos_FullSet_Test_Impl           ", Rr17a_Oos_FullSet_Test_Impl);
        t.add("Rr17a_Oos_parallel_FullSet_Test_Impl  ", Rr17a_Oos_parallel_FullSet_Test_Impl);

        t.add("Rr17a_SM_EmptrySet_Test_Impl          ", Rr17a_SM_EmptrySet_Test_Impl);
        t.add("Rr17a_SM_SingltonSet_Test_Impl        ", Rr17a_SM_SingltonSet_Test_Impl);
        t.add("Rr17a_SM_FullSet_Test_Impl            ", Rr17a_SM_FullSet_Test_Impl);
        t.add("Rr17a_SM_parallel_FullSet_Test_Impl   ", Rr17a_SM_parallel_FullSet_Test_Impl);

        t.add("Rr17b_Oos_EmptrySet_Test_Impl         ", Rr17b_Oos_EmptrySet_Test_Impl);
        t.add("Rr17b_Oos_SingltonSet_Test_Impl       ", Rr17b_Oos_SingltonSet_Test_Impl);
        t.add("Rr17b_Oos_FullSet_Test_Impl           ", Rr17b_Oos_FullSet_Test_Impl);
        t.add("Rr17b_Oos_parallel_FullSet_Test_Impl  ", Rr17b_Oos_parallel_FullSet_Test_Impl);


        t.add("Grr18_Oos_EmptrySet_Test_Impl         ", Grr18_Oos_EmptrySet_Test_Impl);
        t.add("Grr18_Oos_FullSet_Test_Impl           ", Grr18_Oos_FullSet_Test_Impl);
        t.add("Grr18_Oos_parallel_FullSet_Test_Impl  ", Grr18_Oos_parallel_FullSet_Test_Impl);
        t.add("Grr18_Oos_SingltonSet_Test_Impl       ", Grr18_Oos_SingltonSet_Test_Impl);

    });
}
