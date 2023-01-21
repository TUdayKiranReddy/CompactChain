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
        size_t size = 250;

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

        cout << "\n/*----------------Simulation for Transaction proof verification-----------------------------*/" << endl;
        vector<double> time_boneh, time_verify_boneh;


        int len = 125;
        size_t elements_PREV_OUTPUTS = 200;
        size_t elements_CURR_OUTPUTS = 200;
        double time_tx_verify=0.0;
        double time_tx_verify_b=0.0;
        double time_tx_verify_b_mt=0.0;

    
        cout << "\n/*---------Boneh Accumulator Update-----------------*/" << endl;
        // Batch Deletion
        flint::BigMod A_post_delete, A_, A_final, proof_D;
        flint::BigInt p;

        // Let's deletes last 100 elements
        
        vector<flint::BigInt> x_list(elements_PREV_OUTPUTS);
        vector<flint::BigInt> y_list(elements_CURR_OUTPUTS);
        vector<flint::BigInt> reps_y(elements_CURR_OUTPUTS), reps_y_v(elements_CURR_OUTPUTS);
        vector<flint::BigMod> proofs_list(elements_PREV_OUTPUTS);
        vector<future<void>> futures;

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

        vector<flint::BigInt> rep_post_update;
        for(int l=0;l<(size+elements_CURR_OUTPUTS);l++){
            if(l<(size-elements_PREV_OUTPUTS))
                rep_post_update.push_back(representatives[l]);
            else if(l>(size-1))
                rep_post_update.push_back(reps_y[l-size]);
        }

        /*---------Witness generation-----------------*/
        vector<flint::BigMod> W(size + elements_CURR_OUTPUTS - elements_PREV_OUTPUTS);
        RSAAccumulator::witnessesForSet(rep_post_update, rsaKey, W, threadPool);

        int Ntx = 8;
        int avr_itr = 50;
        for(int k=0;k<avr_itr*len;k++){
            int j=0;
            flint::BigInt tx = y_list[j];

            bool ans;
        
            /*---------Witness verification---------------*/
            double verStart = Profiler::getCurrentTime();
            RSAAccumulator::verify(tx, W[j+size-elements_PREV_OUTPUTS], A_final, rsaKey.getPublicKey(), ans);
            double verEnd = Profiler::getCurrentTime();
            time_tx_verify += (verEnd-verStart);
            cout << "\nTime taken to verify single transaction in boneh is " << (verEnd-verStart) << " seconds\n";


            verStart = Profiler::getCurrentTime();
            for(int p=0;p<Ntx;p++){
                RSAAccumulator::verify(y_list[p], W[p+size-elements_PREV_OUTPUTS], A_final, rsaKey.getPublicKey(), ans);
            }
            verEnd = Profiler::getCurrentTime();
            time_tx_verify_b += (verEnd-verStart);
            cout << "\nTime taken to verify " << Ntx << " transaction in boneh is " << (verEnd-verStart) << " seconds\n";

            verStart = Profiler::getCurrentTime();
            for(int p=0;p<Ntx;p++){
                futures.push_back(threadPool.enqueue<void>([&, p](){
                    RSAAccumulator::verify(y_list[p], W[p+size-elements_PREV_OUTPUTS], A_final, rsaKey.getPublicKey(), ans);
                }));
            }
            for(auto& future:futures)
                future.get();
            verEnd = Profiler::getCurrentTime();
            time_tx_verify_b_mt += (verEnd-verStart);
            cout << "\nTime taken to verify " << Ntx << " transaction(parallel) in boneh is " << (verEnd-verStart) << " seconds\n";
            futures.clear();
        }
        time_tx_verify /= (avr_itr*len);
        // time_tx_verify_b /= len;
        // time_tx_verify_b_mt /= len;
        time_tx_verify_b /= avr_itr;
        time_tx_verify_b_mt /= avr_itr;

        std::ofstream file;
        file.open("./results/boneh/FinalTXOVerification.csv");
        file << "Parallel, MemBatch, MemSingle\n";
        cout << "\nAverage time taken to verify single transaction in boneh is " << time_tx_verify << " seconds\n";
        cout << "\nAverage time taken to verify " << Ntx << " transaction in boneh is " << time_tx_verify_b << " seconds\n";
        cout << "\nAverage time taken to verify " << Ntx << " transaction(parrallel) in boneh is " << time_tx_verify_b_mt << " seconds\n";
        file << time_tx_verify_b_mt << "," << time_tx_verify_b << "," << time_tx_verify << "\n";
        file.close();
    }

}  // namespace testproposed