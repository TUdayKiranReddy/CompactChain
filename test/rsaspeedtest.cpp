#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
//#include <bits/stdc++.h>
#include <math.h>

#include <algorithms/RSAAccumulator.hpp>
#include <algorithms/RSAKey.hpp>

#include <utils/Pointers.hpp>
#include <utils/Profiler.hpp>
#include <utils/ThreadPool.hpp>

#include <flint/BigInt.hpp>
#include <flint/BigMod.hpp>
#include <flint/Random.hpp>

using namespace std;

namespace speedtest {
void rsaTest(int setSize);
vector<flint::BigInt> readBigInts(string filename);
}  // namespace speedtest

int main(int argc, char** argv) {
    int setSize;
    if(argc > 1) {
        setSize = atoi(argv[1]);
    } else {
        setSize = 10000;
    }
    speedtest::rsaTest(setSize);
    return 0;
}

namespace speedtest {

vector<flint::BigInt> readBigInts(string filename) {
    ifstream fileIn(filename);
    vector<flint::BigInt> elements;
    string fileLine;
    while(getline(fileIn, fileLine)) {
        flint::BigInt element;
        element.assign(fileLine);
        elements.push_back(move(element));
    }
    return elements;
}

void rsaTest(int setSize) {
    // cout << "RSA Accumulator test:" << endl;
    static const int THREAD_POOL_SIZE = 16;
    ThreadPool threadPool(THREAD_POOL_SIZE);

    vector<flint::BigInt> elements;
    flint::BigInt x;
    //Read a random set from a file
    elements = readBigInts("randomBigInts" + to_string(setSize));
    cout << "Generated " << elements.size() << " random elements." << endl;

    //Generate the public/private key
    double keyGenStart = Profiler::getCurrentTime();
    RSAKey rsaKey;
    RSAAccumulator::genKey(0, 3072, rsaKey);
    double keyGenEnd = Profiler::getCurrentTime();
    cout << "Key generation took " << (keyGenEnd-keyGenStart) << " seconds" << endl;


    cout << "\n/*---------Generate representatives for the elements-----------------*/" << endl;
    //Generate representatives for the elements
    size_t size = 100;
    vector<flint::BigInt> e_1;
    for(size_t i = 0; i < size; i++)
        e_1.push_back(elements[i]);
        
    vector<flint::BigInt> representatives(size);
    double repGenStart = Profiler::getCurrentTime();
    RSAAccumulator::genRepresentatives(e_1, *(rsaKey.getPublicKey().primeRepGenerator),
                                       representatives, threadPool);
    double repGenEnd = Profiler::getCurrentTime();
    cout << "Generated " << representatives.size() << " prime representatives in " << (repGenEnd-repGenStart) << " seconds" << endl;
    
    cout << "\n/*---------Accumulate with private key-----------------*/" << endl;
    //Accumulate the representatives
    flint::BigMod accumulator;
    double accStart = Profiler::getCurrentTime();
    RSAAccumulator::accumulateSetPvt(representatives, rsaKey, accumulator);
    double accEnd = Profiler::getCurrentTime();
    cout << "Accumulated " << representatives.size() << " prime representatives in " << (accEnd-accStart) << " seconds with private key" << endl;
    // cout << (accEnd - accStart) << endl;
    cout << accumulator << endl;
    
    cout << "\n/*---------Accumulate again with only the public information-----------------*/" << endl;
    //Accumulate again with only the public information
    flint::BigMod accPub;
    flint::BigInt product;
    double pubAccStart = Profiler::getCurrentTime();
    RSAAccumulator::accumulateSet(representatives, rsaKey.getPublicKey(), accPub, product);
    double pubAccEnd = Profiler::getCurrentTime();
    cout << "Accumulated " << representatives.size() << " prime representatives in " << (pubAccEnd-pubAccStart) << " seconds with public key" << endl;
    // cout << (pubAccEnd - pubAccStart) << endl;
    //cout  << (rsaKey.getPublicKey().rsaModulus/2 - 1).bitLength() << endl;
    //cout << accPub.getMantissa() << " " << accPub.getMantissa().bitLength() << endl;
    cout << "accPub: " << accPub << endl;
    //cout << product << endl;
   

    if(accumulator != accPub) {
        cout << "Error! Public and private accumulation do not match!" << endl;
        cout << "Private: " << accumulator << endl;
        cout << "Public: " << accPub << endl;
    }
    
    cout << "\n/*---------Batch addition and NI-PoE-----------------*/" << endl;
    // Batch Addition and NI-PoE 
    flint::BigMod prev_acc;
    prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
    prev_acc = rsaKey.getPublicKey().base;
    flint::BigMod acc, Q;
    std::vector<flint::BigInt> rep(e_1.size());
    
    double Start = Profiler::getCurrentTime();
    RSAAccumulator::genRepresentatives(e_1, *(rsaKey.getPublicKey().primeRepGenerator),
                                       rep, threadPool);
    RSAAccumulator::batchAdd(rep, rsaKey, prev_acc, acc, Q);
    double End = Profiler::getCurrentTime();
    cout << "Accumulated " << representatives.size() << " prime representatives in " << (End-Start) << " seconds with public key" << endl;
    cout << acc << endl;
    if(accumulator == acc) 
        cout << "\nAccumulator generated through Public and private information does match!" << endl;
    cout << "\nNI-PoE Proof:" << Q << endl;

    cout << "\n/*---------Create Non Membership Proof and Verfy-----------------*/" << endl;
    // CreateNonMemWit and VerfyNonMEmWit
    flint::BigInt x_k = elements[9999];
    flint::BigMod d;
    flint::BigInt b;

    RSAAccumulator::CreateNonMemWit(x_k, rep, rsaKey, prev_acc, d, b);
    bool ans;
    RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, acc, prev_acc, d, b, ans);
    
    if(ans)
        cout << "\nNon Membership Witness verified!" << endl;
    else
        cout << "\nNon Membership Witness not verified!!" << endl;
    
    // Updating Accumulator again to update non membership witness for checking
    vector<flint::BigInt> e_2;
    for(size_t i = size; i < 100+size; i++)
        e_2.push_back(elements[i]);
    std::vector<flint::BigInt> rep_1(e_2.size());
    flint::BigMod acc_post;
    flint::BigMod q;
    RSAAccumulator::genRepresentatives(e_2, *(rsaKey.getPublicKey().primeRepGenerator),
                                       rep_1, threadPool);
    RSAAccumulator::batchAdd(rep_1, rsaKey, acc, acc_post, q);

    cout << "\n/*---------Update Non Membership Proof and Verfy-----------------*/" << endl;
    flint::BigMod new_d;
    flint::BigInt new_b;
    bool ans1;
    std::vector<flint::BigInt> rep_e2(e_2.size());

    RSAAccumulator::genRepresentatives(e_2, *(rsaKey.getPublicKey().primeRepGenerator),
                                       rep_e2, threadPool);
    RSAAccumulator::UpNonMemWit(x_k, d, b, rep_e2, rsaKey, acc, new_d, new_b);

    RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, acc_post, prev_acc, new_d, new_b, ans1);
    
    if(ans1)
        cout << "\nNon Membership Witness verified!" << endl;
    else
        cout << "\nNon Membership Witness not verified!!" << endl;
    // cout << "\n/*---------Witnesses Creation-----------------*/" << endl;
    // // Witness Creation
    // vector<flint::BigMod> witnesses(size);
    // double memStart = Profiler::getCurrentTime();
    // RSAAccumulator::witnessesForSet(rep, rsaKey.getPublicKey(), witnesses, threadPool);
    // double memEnd = Profiler::getCurrentTime();
    // cout << "\nGenerated "<< size << " Members witnesses in " << (memEnd-memStart) << " seconds with public key" << endl;

    // cout << "\n/*---------Witnesses verfication-----------------*/" << endl;
    // //Verify the public-key witnesses, just in case they're different
    // bool verifyPassed;
    // double verifyPubStart = Profiler::getCurrentTime();
    // for(size_t i = 0; i < e_1.size(); i++) {
    //     RSAAccumulator::verify(e_1.at(i), witnesses.at(i), acc, rsaKey.getPublicKey(), verifyPassed);
    //     if(!verifyPassed) {
    //         cout << "\nWitness for element " << i << " did not pass!" << endl;
    //     }
    // }
    // double verifyPubEnd = Profiler::getCurrentTime();
    // cout << "\nVerified " << e_1.size() << " elements in " << (verifyPubEnd-verifyPubStart) << " seconds against public accumulator" << endl;

    // cout << "\n/*---------Batch Deletion with NI-PoE-----------------*/" << endl;
    // // Batch Deletion
    // flint::BigMod A_post_delete, proof;
    // flint::BigInt p;

    // // Let's deletes last 100 elements
    // size_t nDelets = 50;
    // vector<flint::BigInt> x_list(nDelets);
    // vector<flint::BigMod> proofs_list(nDelets);
    // for(size_t i=0;i<nDelets;i++){
    //     x_list[i] = e_1[size  -1 - i];
    //     proofs_list[i] = witnesses[size  - 1 - i];
    // }
    // double deleteStart = Profiler::getCurrentTime();
    // RSAAccumulator::batch_delete_using_membership_proofs(acc, x_list, proofs_list, rsaKey.getPublicKey(), *(rsaKey.getPublicKey().primeRepGenerator),
    //                                                      A_post_delete, p, proof, threadPool);
    // double deleteEnd = Profiler::getCurrentTime();

    // cout << "\nDeleted "<< nDelets << " Members  in " << (deleteEnd-deleteStart) << " seconds with Proof generation." << endl;

    // cout << "\n/*---------Proof verfication of BatchDelete-----------------*/" << endl;
    // // Proof verification
    // bool isVerify;
    // vector<flint::BigInt> rep_v(nDelets);

    // double verStart = Profiler::getCurrentTime();
    // RSAAccumulator::genRepresentatives(x_list, *(rsaKey.getPublicKey().primeRepGenerator), rep_v, threadPool);
    // RSAAccumulator::NIPoE_Verify(rsaKey, rep_v, *(rsaKey.getPublicKey().primeRepGenerator), A_post_delete, acc, proof, isVerify);
    // double verEnd = Profiler::getCurrentTime();
    // if(isVerify)
    //     cout << "\nBatch Deletion of " << nDelets << " members verified!" << endl;
    // else
    //     cout << "\nBatch Deletion of " << nDelets << " members not verified!!" << endl;
    // cout << "\nVerfied "<< nDelets << " members after batch Deletion in " << (verEnd-verStart) << " seconds." << endl;
    // double StartVerify = Profiler::getCurrentTime();
    // bool b;
    // RSAAccumulator::NIPoE_Verify(e_1, threadPool,rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, acc, Q, b);
    // double EndVerify = Profiler::getCurrentTime();
    // if(b == 1)
    //     cout << "NI-PoE proof for the commitment is verified successfully" << endl;
    // else
    //     cout << "NI-PoE proof verification failed" << endl;
    // cout << "NI-PoE verification time for 1000 elements:" << (EndVerify - StartVerify) << " seconds" << endl;

    // /*--------------------------Simulation Accumulator update----------------*/
    // cout << "/*----------------Simulation for Accumulator update-----------------------------*/" << endl;
    // //flint::BigMod prev_acc;
    // prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
    // prev_acc = rsaKey.getPublicKey().base;
    // vector<double> time_minichain, time_proposed, time_verify_minichain, time_verify_proposed;
    // size_t len = 10;
    // for(size_t i = 0; i < len; i++) {
    //     vector<flint::BigInt> elements_TXO, elements_STXO;
    //     flint::BigMod TXO_C, STXO_C, A, Q_TXO, Q_STXO, Q_A;
    // //  prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
    // //  prev_acc = rsaKey.getPublicKey().base;
    //     for(size_t j = 0; j < (i+1)*100; j++){
    //         elements_STXO.push_back(elements[j]);
    //         //cout << j << endl;
            
    //         elements_TXO.push_back(elements[j+1000]);
    //         //cout << j+1000 << endl;
    //     }
    //     std::vector<flint::BigInt> rep_A(elements_STXO.size()), rep_STXO(elements_STXO.size()), rep_TXO(elements_TXO.size());
    //     // Minichain's accumulator update
    //     double Start = Profiler::getCurrentTime();
    //     RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_A, threadPool);
    //     RSAAccumulator::batchAdd(rep_A, rsaKey, prev_acc, A, Q_A);
    //     double End = Profiler::getCurrentTime();
    //     time_minichain.push_back(End - Start);
    //     //cout << "Minichain's time" << (End - Start) << endl;
        
    //     // Proposed stateless blockchain's accumulator update
    //     Start = Profiler::getCurrentTime();
    //     RSAAccumulator::genRepresentatives(elements_TXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_TXO, threadPool);
    //     RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_STXO, threadPool);
    //     RSAAccumulator::batchAdd(rep_TXO, rsaKey, prev_acc, TXO_C, Q_TXO);
    //     RSAAccumulator::batchAdd(rep_STXO, rsaKey, prev_acc, STXO_C, Q_STXO);
    //     End = Profiler::getCurrentTime();
    //     time_proposed.push_back(End - Start);
    // //  cout << "proposed protocol's time" << (End - Start) << endl;
        
    //     double StartVerify = Profiler::getCurrentTime();
    //     bool b;
    //     RSAAccumulator::NIPoE_Verify(elements_STXO, threadPool,rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, A, Q_A, b);
    //     double EndVerify = Profiler::getCurrentTime();
    //     time_verify_minichain.push_back(EndVerify - StartVerify);
    //     if(b == 1)
    //         cout << "NI-PoE proof for the minichain's STXO_C  is verified successfully" << endl;
    //     else
    //         cout << "NI-PoE proof verification for the minichain's STXO_C failed" << endl;
        
    //     StartVerify = Profiler::getCurrentTime();
    //     bool b_TXO;
    //     RSAAccumulator::NIPoE_Verify(elements_TXO, threadPool, rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, TXO_C, Q_TXO, b_TXO);
    //     bool b_STXO;
    //     RSAAccumulator::NIPoE_Verify(elements_STXO, threadPool, rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, STXO_C, Q_STXO, b_STXO);
    //     EndVerify = Profiler::getCurrentTime();
    //     time_verify_proposed.push_back(EndVerify - StartVerify);
    //     if(b_TXO == 1)
    //         cout << "NI-PoE proof for the proposed protocol's TXO_C  is verified successfully" << endl;
    //     else
    //         cout << "NI-PoE proof verification for the proposed protocol's TXO_C failed" << endl;
        
    //     if(b_STXO == 1)
    //         cout << "NI-PoE proof for the proposed protocol's STXO_C  is verified successfully" << endl;
    //     else
    //         cout << "NI-PoE proof verification for the proposed protocol's STXO_C failed" << endl;
        
    // }
    // std::ofstream file;
    // file.open("testAccUp_result.csv");
    // file << "N,Minichain,Proposed\n";
    // cout << "\n/*-----------------Accumulator Update time-----------------------------*/" << endl;
    // for(size_t i = 0; i < len; ++i) {
    //     cout << "\n/*-----------Numeber of elements: " << (i+1)*100 << " -----------------*/" << endl;
    //     cout << "Minichain accumulator update time: " << time_minichain.at(i) << " seconds"  << endl;
    //     cout << "Proposed accumulator update time : " << time_proposed.at(i) << " seconds" << endl;
    //     file << to_string((i+1)*100)+","+to_string(time_minichain.at(i))+","+to_string(time_proposed.at(i))+"\n";
    // }
    // file.close();
    
    // file.open("testAccVer_result.csv");
    // file << "N,Minichain,Proposed\n";
    // cout << "\n/*-----------------Accumulator verification time------------------------------------*/" << endl;
    // for(size_t i = 0; i < len; ++i) {
    //     cout << "\n/*-----------Numeber of elements: " << (i+1)*100 << " -----------------*/" << endl;
    //     cout << "NI-PoE verification time for the minichain " << time_verify_minichain.at(i) << " seconds" << endl;
    //     cout << "NI-PoE verification time for the proposed  " << time_verify_proposed.at(i) << " seconds" << endl;
    //     file << to_string((i+1)*100)+","+to_string(time_verify_minichain.at(i))+","+to_string(time_verify_proposed.at(i))+"\n";
    // }
 }

}  // namespace speedtest