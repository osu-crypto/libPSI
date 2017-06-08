#include "cryptoTools/Common/Log.h"
#include <functional>

#include "AknBfPsi_Tests.h"
//#include "nkOt_Tests.h"
//#include "BaseOT_Tests.h"
//#include "OT_Tests.h"
//#include "NcoOT_Tests.h"
#include "AknBfPsi_Tests.h"
#include "BinOtPsi_Tests.h"

#include "ShamirSSScheme_Tests.h"
#include "DcwBfPsi_Tests.h"
#include "DktMPsi_Tests.h"

#include "BgiPirTests.h"

using namespace osuCrypto;

void run(std::string name, std::function<void(void)> func)
{
    std::cout << name;
    std::cout << std::flush;
    auto start = std::chrono::high_resolution_clock::now();
    try
    {
        func(); std::cout << Color::Green << "  Passed" << ColorDefault;
    }
    catch (const std::exception& e)
    {
        std::cout << Color::Red << "Failed - " << e.what() << ColorDefault;
    }

    auto end = std::chrono::high_resolution_clock::now();

    u64 time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "   " << time << "ms" << std::endl;


}


void kkrt_psi_all()
{
    std::cout << std::endl;
    run("Psi_kkrt_EmptySet_Test_Impl         ", Psi_kkrt_EmptySet_Test_Impl);
    //run("Psi_kkrt_FullSet_Test_Impl           ", Psi_kkrt_FullSet_Test_Impl);
    //run("Psi_kkrt_SingletonSet_Test_Impl       ", Psi_kkrt_SingletonSet_Test_Impl);

}

//void bitVec_all()
//{
//    std::cout << std::endl;
//    run("BitVector_Indexing_Test                 ", BitVector_Indexing_Test_Impl);
//    run("BitVector_Parity                        ", BitVector_Parity_Test_Impl);
//    run("BitVector_Append_Test                   ", BitVector_Append_Test_Impl);
//    run("BitVector_Copy_Test                     ", BitVector_Copy_Test_Impl);
//}
//
//void OT_all()
//{
//    std::cout << std::endl;
//
//    run("Transpose_Test_Impl                     ", Transpose_Test_Impl);
//    run("KosOtExt_100Receive_Test_Impl           ", KosOtExt_100Receive_Test_Impl);
//    run("LzKosOtExt_100Receive_Test_Impl         ", LzKosOtExt_100Receive_Test_Impl);
//    run("IknpOtExt_100Receive_Test_Impl          ", IknpOtExt_100Receive_Test_Impl);
//    run("AknOt_sendRecv1000_Test                 ", AknOt_sendRecv1000_Test);
//    run("KkrtNcoOt_Test                          ", KkrtNcoOt_Test_Impl);
//    run("OosNcoOt_Test_Impl                      ", OosNcoOt_Test_Impl);
//    run("LinearCode_Test_Impl                       ", LinearCode_Test_Impl);
//    run("NaorPinkasOt_Test                       ", NaorPinkasOt_Test_Impl);
//}
////
//
//void Ecc_all()
//{
//    std::cout << std::endl;
//
//    run("Ecc2mNumber_Test                        ", Ecc2mNumber_Test);
//    run("Ecc2mPoint_Test                         ", Ecc2mPoint_Test);
//    run("EccpNumber_Test                         ", EccpNumber_Test);
//    run("EccpPoint_Test                          ", EccpPoint_Test);
//
//}
//



void DktPsi_all()
{ 
    std::cout << std::endl;
    run("DktPsi_EmptrySet_Test_Impl              ", DktMPsi_EmptrySet_Test_Impl);
    run("DktPsi_FullSet_Test_Impl                ", DktMPsi_FullSet_Test_Impl);
    run("DktPsi_SingltonSet_Test_Imp             ", DktMPsi_SingltonSet_Test_Impl);
}


void DcwPsi_all()
{
    std::cout << std::endl;
    run("DcwPsi_EmptrySet_Test_Impl              ", DcwBfPsi_EmptrySet_Test_Impl);
    run("DcwPsi_FullSet_Test_Impl                ", DcwBfPsi_FullSet_Test_Impl);
    run("DcwPsi_SingltonSet_Test_Imp             ", DcwBfPsi_SingltonSet_Test_Impl);
}

void AknBfPsi_all()
{
    std::cout << std::endl;
    run("AknBfPsi_EmptrySet_Test_Impl            ", AknBfPsi_EmptrySet_Test_Impl);
    run("AknBfPsi_FullSet_Test_Impl              ", AknBfPsi_FullSet_Test_Impl);
    run("AknBfPsi_SingltonSet_Test_Impl          ", AknBfPsi_SingltonSet_Test_Impl);
}
void OtBinPsi_all()
{
    std::cout << std::endl;
    //run("CuckooHasher_Test_Impl          ", CuckooHasher_Test_Impl);
    //run("Rr17a_Kkrt_EmptrySet_Test_Impl        ", Rr17a_Kkrt_EmptrySet_Test_Impl);
    //run("Rr17a_Kkrt_FullSet_Test_Impl          ", Rr17a_Kkrt_FullSet_Test_Impl);
    //run("Rr17a_Kkrt_SingltonSet_Test_Impl      ", Rr17a_Kkrt_SingltonSet_Test_Impl);

    //run("Rr17a_Oos_EmptrySet_Test_Impl         ", Rr17a_Oos_EmptrySet_Test_Impl);
    //run("Rr17a_Oos_FullSet_Test_Impl           ", Rr17a_Oos_FullSet_Test_Impl);
    //run("Rr17a_Oos_SingltonSet_Test_Impl       ", Rr17a_Oos_SingltonSet_Test_Impl);

    run("Rr17b_Oos_EmptrySet_Test_Impl         ", Rr17b_Oos_EmptrySet_Test_Impl);
    run("Rr17b_Oos_FullSet_Test_Impl           ", Rr17b_Oos_FullSet_Test_Impl);
    run("Rr17b_Oos_SingltonSet_Test_Impl       ", Rr17b_Oos_SingltonSet_Test_Impl);

}

void ShamirSSScheme_all()
{
    std::cout << std::endl;
    run("ShamirSSScheme_GF2X_Test                 ", ShamirSSScheme_Test);
}


void BGI_PIR_all()
{
    std::cout << std::endl;
    run("BGI_keyGen_Test                 ", BgiPir_keyGen_test);
    run("BGI_PIR_Test                    ", BgiPir_PIR_test);
    run("BgiPir_FullDomain_test          ", BgiPir_FullDomain_test);
}

void drrn_psi_all()
{
    std::cout << std::endl;
    // run("Psi_drrn_EmptySet_Test_Impl         ", Psi_drrn_EmptySet_Test_Impl);
    // run("Psi_drrn_FullSet_Test_Impl           ", Psi_drrn_FullSet_Test_Impl);
    run("Psi_drrn_SingletonSet_Test_Impl       ", Psi_drrn_SingletonSet_Test_Impl);

}


void run_all()
{
    //LinearCode_Test_Impl();
    //run("OosNcoOt_Test_Impl                      ", OosNcoOt_Test_Impl);
    //run("KkrtNcoOt_Test                          ", KkrtNcoOt_Test_Impl);
    //run("Rr17a_Oos_SingltonSet_Test_Impl       ", Rr17a_Oos_SingltonSet_Test_Impl);

    //run("Rr17a_Kkrt_SingltonSet_Test_Impl      ", Rr17a_Kkrt_SingltonSet_Test_Impl);
    //NetWork_all();
    //bitVec_all();
    //Ecc_all();
    //OT_all();
    //kkrt_psi_all();
    //AknBfPsi_all();
    //OtBinPsi_all();
    //DcwPsi_all();
    //DktPsi_all();
    //BGI_PIR_all();
    drrn_psi_all();
}
