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
#include "BgiPirTests.h"
#include "DrrnPsi_Tests.h"
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


        t.add("BgiPir_keyGen_128_test                ", BgiPir_keyGen_128_test);
        t.add("BgiPir_keyGen_test();                 ", BgiPir_keyGen_test);
        t.add("BgiPir_PIR_test();                    ", BgiPir_PIR_test);
        t.add("BgiPir_FullDomain_test();             ", BgiPir_FullDomain_test);
        t.add("BgiPir_FullDomain_iterator_test();    ", BgiPir_FullDomain_iterator_test);
        t.add("BgiPir_FullDomain_multikey_test();    ", BgiPir_FullDomain_multikey_test);


        t.add("Psi_drrn_SingletonSet_Test_Impl       ", Psi_drrn_SingletonSet_Test_Impl);
        t.add("Psi_drrn_FullSet_Test_Impl            ", Psi_drrn_FullSet_Test_Impl);
        t.add("Psi_drrn_EmptySet_Test_Impl           ", Psi_drrn_EmptySet_Test_Impl);

        //t.add("DktPsi_EmptrySet_Test_Impl            ", DktMPsi_EmptrySet_Test_Impl);
        //t.add("DktPsi_FullSet_Test_Impl              ", DktMPsi_FullSet_Test_Impl);
        //t.add("DktPsi_SingltonSet_Test_Imp           ", DktMPsi_SingltonSet_Test_Impl);


        t.add("DcwPsi_EmptrySet_Test_Impl            ", DcwRBfPsi_EmptrySet_Test_Impl);
        t.add("DcwPsi_FullSet_Test_Impl              ", DcwRBfPsi_FullSet_Test_Impl);
        t.add("DcwPsi_SingltonSet_Test_Imp           ", DcwRBfPsi_SingltonSet_Test_Impl);

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
