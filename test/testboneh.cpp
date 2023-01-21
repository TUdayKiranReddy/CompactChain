#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>
#include <math.h>

#include <algorithms/RSAAccumulator.hpp>
#include <algorithms/RSAKey.hpp>

#include <utils/Pointers.hpp>
#include <utils/Profiler.hpp>
#include <utils/ThreadPool.hpp>
#include <utils/LibConversions.hpp>

#include <flint/BigInt.hpp>
#include <flint/BigMod.hpp>
#include <flint/Random.hpp>

using namespace std;

namespace testproposed {
void test(size_t setSize, string index);
vector<flint::BigInt> readBigInts(string filename);
}  // namespace testAccUp

int main(int argc, char** argv) {
    size_t setSize;
    int idx;
    if(argc > 1) {
        idx = atoi(argv[1]);
    } else {
        idx = 0;
    }
    ostringstream index;
    index << idx;
    setSize = 10000;
    testproposed::test(setSize, index.str());

    return 0;
}

namespace testproposed {

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

    void test(size_t setSize, string index) {
        // cout << "RSA Accumulator test:" << endl;
        static const int THREAD_POOL_SIZE = 16;
        static const int RSA_KEY_SIZE = 3072; //bits
        size_t size = 2000;

        ThreadPool threadPool(THREAD_POOL_SIZE);
        // ThreadPool threadPool_half(THREAD_POOL_SIZE/2);

        vector<flint::BigInt> elements;
        flint::BigInt x;

        //Read a random set from a file
        elements = readBigInts("randomBigInts" + to_string(setSize));
        cout << "Generated " << elements.size() << " random elements." << endl;

        //Generate the public/private key
        double keyGenStart = Profiler::getCurrentTime();
        RSAKey rsaKey;
        RSAAccumulator::genKey(0, RSA_KEY_SIZE, rsaKey);
        double keyGenEnd = Profiler::getCurrentTime();
        cout << "Key generation took " << (keyGenEnd-keyGenStart) << " seconds" << endl;

        cout << "\n/*---------Generate representatives for the elements-----------------*/" << endl;
        //Generate representatives for the elements
        
        vector<flint::BigInt> e_1;
        for(size_t i = 0; i < size; i++)
            e_1.push_back(elements[i]);
            
        vector<flint::BigInt> representatives(size);
        double repGenStart = Profiler::getCurrentTime();
        RSAAccumulator::genRepresentatives(e_1, *(rsaKey.getPublicKey().primeRepGenerator),
                                           representatives, threadPool);
        double repGenEnd = Profiler::getCurrentTime();
        cout << "Generated " << representatives.size() << " prime representatives in " << (repGenEnd-repGenStart) << " seconds" << endl;


        cout << "\n/*---------Accumulate again with only the public information-----------------*/" << endl;
        //Accumulate again with only the public information
        flint::BigMod accPub;
        flint::BigInt product;
        double pubAccStart = Profiler::getCurrentTime();
        RSAAccumulator::accumulateSet(representatives, rsaKey.getPublicKey(), accPub, product);
        double pubAccEnd = Profiler::getCurrentTime();
        cout << "Accumulated " << representatives.size() << " prime representatives in " << (pubAccEnd-pubAccStart) << " seconds with public key" << endl;
        cout << "accPub: " << accPub << endl;

        cout << "\n/*---------Batch addition and NI-PoE-----------------*/" << endl;
        // Batch Addition and NI-PoE 
        flint::BigMod prev_acc;
        prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
        prev_acc = rsaKey.getPublicKey().base;
        flint::BigMod acc, Q;
        double Start = Profiler::getCurrentTime();
        RSAAccumulator::batchAdd(representatives, rsaKey, prev_acc, acc, Q);
        double End = Profiler::getCurrentTime();
        cout << "Accumulated " << representatives.size() << " prime representatives in " << (End-Start) << " seconds with public key" << endl;
        cout << acc << endl;
        cout << "\nNI-PoE Proof:" << Q << endl;

        cout << "\n/*---------Witnesses Creation-----------------*/" << endl;
        // Witness Creation
        vector<flint::BigMod> witnesses(size);
        double memStart = Profiler::getCurrentTime();
        RSAAccumulator::witnessesForSet(representatives, rsaKey, witnesses, threadPool);
        double memEnd = Profiler::getCurrentTime();
        cout << "\nGenerated "<< size << " Members witnesses in " << (memEnd-memStart) << " seconds with public key" << endl;

        cout << "\n/*---------Witnesses verfication-----------------*/" << endl;
        //Verify the public-key witnesses, just in case they're different
        bool verifyPassed;
        double verifyPubStart = Profiler::getCurrentTime();
        for(size_t i = 0; i < e_1.size(); i++) {
            RSAAccumulator::verify(e_1.at(i), witnesses.at(i), acc, rsaKey.getPublicKey(), verifyPassed);
            if(!verifyPassed) {
                cout << "\nWitness for element " << i << " did not pass!" << endl;
            }
        }
        double verifyPubEnd = Profiler::getCurrentTime();
        cout << "\nVerified " << e_1.size() << " elements in " << (verifyPubEnd-verifyPubStart) << " seconds against public accumulator" << endl;

        cout << "\n/*----------------Simulation for Accumulator update-----------------------------*/" << endl;
        vector<double> time_boneh, time_verify_boneh, time_proposed, time_verify_proposed;

        int step = 200;
        int len = 5;

        for(int k=0;k<len;k++){
            cout << "\n/*---------Boneh Accumulator Update-----------------*/" << endl;
            cout << "Itr:- " << k << endl;
            // Batch Deletion
            flint::BigMod A_post_delete, A_, A_final, proof_D;
            flint::BigInt p;
            vector<future<void>> futures;
            vector<flint::BigMod>::size_type itr = 0;

            // Let's deletes last 100 elements
            size_t elements_PREV_OUTPUTS = step*(k+1);
            size_t elements_CURR_OUTPUTS = step*(k+1);

            vector<flint::BigInt> x_list(elements_PREV_OUTPUTS);
            vector<flint::BigInt> y_list(elements_CURR_OUTPUTS);
            vector<flint::BigInt> reps_y(elements_CURR_OUTPUTS), reps_y_v(elements_CURR_OUTPUTS);
            vector<flint::BigMod> proofs_list(elements_PREV_OUTPUTS);


            flint::BigMod Q_A;
            for(size_t i=0;i<elements_PREV_OUTPUTS;i++){
                x_list[i] = e_1[size  -1 - i];
                proofs_list[i] = witnesses[size  - 1 - i];
            }
            for(size_t i=0;i<elements_CURR_OUTPUTS;i++)
                y_list[i] = elements[size+i];

            double deleteStart = Profiler::getCurrentTime();
                RSAAccumulator::batch_delete_using_membership_proofs(acc, x_list, proofs_list, rsaKey.getPublicKey(), *(rsaKey.getPublicKey().primeRepGenerator),
                                                                     A_post_delete, p, proof_D, threadPool);
                A_ = A_post_delete;
                RSAAccumulator::genRepresentatives(y_list, *(rsaKey.getPublicKey().primeRepGenerator), reps_y, threadPool);
                RSAAccumulator::batchAdd(reps_y, rsaKey, A_, A_final, Q_A);
            double deleteEnd = Profiler::getCurrentTime();
            time_boneh.push_back(deleteEnd-deleteStart);

            cout << "\nDeleted "<< elements_PREV_OUTPUTS << " Members  in " << (deleteEnd-deleteStart) << " seconds with Proof generation." << endl;

            /*---------Proof verfication of Accumulator update-----------------*/
            
            bool isVerify_D, isVerify_A;
            vector<flint::BigInt> rep_v(elements_PREV_OUTPUTS);

            double verStart = Profiler::getCurrentTime();
                RSAAccumulator::genRepresentatives(x_list, *(rsaKey.getPublicKey().primeRepGenerator), rep_v, threadPool);
                RSAAccumulator::genRepresentatives(y_list, *(rsaKey.getPublicKey().primeRepGenerator), reps_y_v, threadPool);
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                    RSAAccumulator::NIPoE_Verify(rsaKey, rep_v, *(rsaKey.getPublicKey().primeRepGenerator), A_post_delete, acc, proof_D, isVerify_D);
                }));
                itr++;
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                    RSAAccumulator::NIPoE_Verify(rsaKey, reps_y_v, *(rsaKey.getPublicKey().primeRepGenerator), A_, A_final, Q_A, isVerify_A);
                }));
                for(auto& future:futures)
                    future.get();
            double verEnd = Profiler::getCurrentTime();
            time_verify_boneh.push_back(verEnd - verStart);

            if(isVerify_D)
                cout << "\nBatch Deletion of " << elements_PREV_OUTPUTS << " members verified!" << endl;
            else
                cout << "\nBatch Deletion of " << elements_PREV_OUTPUTS << " members not verified!!" << endl;

            if(isVerify_A)
                cout << "\nBatch Addition of " << elements_CURR_OUTPUTS << " members verified!" << endl;
            else
                cout << "\nBatch Addition of " << elements_CURR_OUTPUTS << " members not verified!!" << endl;
            cout << "\nVerfied "<< elements_PREV_OUTPUTS << " members after batch Deletion and batch Addition in " << (verEnd-verStart) << " seconds." << endl;

            size_t TXO_SIZE = (k+1)*step;
            size_t STXO_SIZE = (k+1)*step;
                
            flint::BigMod prev_acc_txo(acc), prev_acc_stxo(acc);

            vector<flint::BigInt> elements_TXO, elements_STXO;
            flint::BigMod TXO_C, STXO_C, Q_TXO, Q_STXO;
            vector<flint::BigInt> txo_rep(TXO_SIZE), stxo_rep(STXO_SIZE);
            
            itr = 0;
            futures.clear();

            // Setting Random elements to each Set
            for(size_t j = size; j < size + STXO_SIZE; j++)
                elements_STXO.push_back(elements[j]);

            for(size_t j = size + STXO_SIZE; j < size + STXO_SIZE + TXO_SIZE; j++)
                elements_TXO.push_back(elements[j]);

            // Proposed stateless blockchain's accumulator update
            Start = Profiler::getCurrentTime();
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                        RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator), stxo_rep, threadPool);
                    }));
                itr++;
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                        RSAAccumulator::genRepresentatives(elements_TXO, *(rsaKey.getPublicKey().primeRepGenerator), txo_rep, threadPool);
                    }));
                
                for(auto& future : futures) {
                    future.get();
                }
                itr = 0;
                futures.clear();
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                        RSAAccumulator::batchAdd(txo_rep, rsaKey, prev_acc_txo, TXO_C, Q_TXO);
                    }));
                itr++;
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                        RSAAccumulator::batchAdd(stxo_rep, rsaKey, prev_acc_stxo, STXO_C, Q_STXO);
                    }));
                
                for(auto& future : futures) {
                    future.get();
                }
            End = Profiler::getCurrentTime();

            time_proposed.push_back(End - Start);
            //cout << "proposed protocol's time" << (End - Start) << endl;


            // Proposed stateless blockchain's accumulator update Verfication
            itr = 0;
            futures.clear();
            
            double verifytime = 0.0;
            for(int k=0;k<10;k++){
                bool b_TXO, b_STXO;
                vector<flint::BigInt> txo_rep_V(TXO_SIZE), stxo_rep_V(STXO_SIZE);
                double StartVerify = Profiler::getCurrentTime();
                    futures.push_back(threadPool.enqueue<void>([&, itr]() {
                            RSAAccumulator::genRepresentatives(elements_TXO, *(rsaKey.getPublicKey().primeRepGenerator), txo_rep_V, threadPool);
                        }));
                    itr++;
                    futures.push_back(threadPool.enqueue<void>([&, itr]() {
                            RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator), stxo_rep_V, threadPool);
                        }));
                    
                    for(auto& future : futures) {
                        future.get();
                    }
                    itr = 0;
                    futures.clear();
                    futures.push_back(threadPool.enqueue<void>([&, itr]() {
                            RSAAccumulator::NIPoE_Verify(rsaKey, txo_rep_V, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc_txo, TXO_C, Q_TXO, b_TXO);
                        }));
                    itr++;
                    futures.push_back(threadPool.enqueue<void>([&, itr]() {
                            RSAAccumulator::NIPoE_Verify(rsaKey, stxo_rep_V, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc_stxo, STXO_C, Q_STXO, b_STXO);
                        }));
                    
                    for(auto& future : futures) {
                        future.get();
                    }  
                double EndVerify = Profiler::getCurrentTime();
                itr=0;
                futures.clear();
                verifytime += (EndVerify - StartVerify);
                if(b_TXO == 1)
                    cout << "NI-PoE proof for the proposed protocol's TXO_C  is verified successfully" << endl;
                else
                    cout << "NI-PoE proof verification for the proposed protocol's TXO_C failed" << endl;
                
                if(b_STXO == 1)
                    cout << "NI-PoE proof for the proposed protocol's STXO_C  is verified successfully" << endl;
                else
                    cout << "NI-PoE proof verification for the proposed protocol's STXO_C failed" << endl;
                cout << "\nVerification of Proposed algorithm done in " << (EndVerify - StartVerify) << " seconds.\n";

            }
            time_verify_proposed.push_back(verifytime/10);
            
            cout << "\nVerification of Proposed algorithm done in " << verifytime/10 << " seconds.\n";
        }
        
        std::ofstream file, file1;
        file.open("./results/boneh/FinalAccUp.csv");
        file << "N,Time taken\n";
        file1.open("./results/proposed/FinalAccUp.csv");
        file1 << "N,Time taken\n";
        cout << "\n/*-----------------Accumulator Update time-----------------------------*/" << endl;
        for(size_t i = 0; i < len; i++) {
            cout << "\n/*-----------Number of elements: " << (i+1)*step << " -----------------*/" << endl;
            cout << "Boneh accumulator update time : " << time_boneh.at(i) << " seconds" << endl;
            cout << "Proposed accumulator update time : " << time_proposed.at(i) << " seconds" << endl;
            file << to_string((i+1)*step)+","+to_string(time_boneh.at(i))+"\n";
            file1 << to_string((i+1)*step)+","+to_string(time_proposed.at(i))+"\n";
        }
        file.close();
        file1.close();

        file.open("./results/boneh/FinalAccVer.csv");
        file << "N,Time taken\n";
        file1.open("./results/proposed/FinalAccVer.csv");
        file1 << "N,Time taken\n";
        cout << "\n/*-----------------Accumulator verification time------------------------------------*/" << endl;
        for(size_t i = 0; i < len; i++) {
            cout << "\n/*-----------Number of elements: " << (i+1)*step << " -----------------*/" << endl;
            cout << "NI-PoE verification time for the boneh's algorithm is  " << time_verify_boneh.at(i) << " seconds" << endl;
            cout << "NI-PoE verification time for the proposed's algorithm is  " << time_verify_proposed.at(i) << " seconds" << endl;
            file << to_string((i+1)*step)+","+to_string(time_verify_boneh.at(i))+"\n";
            file1 << to_string((i+1)*step)+","+to_string(time_verify_proposed.at(i))+"\n";
        }
        file.close();
        file1.close();
    }

}  // namespace testproposed