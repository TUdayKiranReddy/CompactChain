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
    size_t size = 1000;

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
    cout << "Yo!";
    //Generate representatives for the elements
    cout << elements[0]; 
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

	/*--------------------------Simulation Accumulator update----------------*/
	cout << "/*----------------Simulation for Accumulator update-----------------------------*/" << endl;
	//flint::BigMod prev_acc;
	prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
	prev_acc = rsaKey.getPublicKey().base;
	vector<double> time_proposed, time_verify_proposed;

    flint::BigMod prev_acc_txo(prev_acc), prev_acc_stxo(prev_acc);

    size_t len = 5;
    int step = 200;
	for(size_t i = 0; i < len; i++) {
	    // Setting size of sets
        size_t TXO_SIZE = (i+1)*step;
        size_t STXO_SIZE = (i+1)*step;
    
        vector<flint::BigInt> elements_TXO, elements_STXO;
		flint::BigMod TXO_C, STXO_C, Q_TXO, Q_STXO;
        vector<flint::BigInt> txo_rep(TXO_SIZE), stxo_rep(STXO_SIZE);
        vector<flint::BigInt> txo_rep_V(TXO_SIZE), stxo_rep_V(STXO_SIZE);
        vector<flint::BigMod>::size_type itr = 0;
        vector<future<void>> futures;

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
        bool b_TXO, b_STXO;
        
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
        
        futures.clear();
		time_verify_proposed.push_back(EndVerify - StartVerify);
		if(b_TXO == 1)
			cout << "NI-PoE proof for the proposed protocol's TXO_C  is verified successfully" << endl;
		else
			cout << "NI-PoE proof verification for the proposed protocol's TXO_C failed" << endl;
		
		if(b_STXO == 1)
			cout << "NI-PoE proof for the proposed protocol's STXO_C  is verified successfully" << endl;
		else
			cout << "NI-PoE proof verification for the proposed protocol's STXO_C failed" << endl;
		
	}
    std::ofstream file;
    file.open("./results/proposed/Data/testAccUp_result"+ index +".csv");
    file << "N,Time taken\n";
	cout << "\n/*-----------------Accumulator Update time-----------------------------*/" << endl;
	for(size_t i = 0; i < len; i++) {
		cout << "\n/*-----------Number of elements: " << (i+1)*step << " -----------------*/" << endl;
		cout << "Proposed accumulator update time : " << time_proposed.at(i) << " seconds" << endl;
        file << to_string((i+1)*step)+","+to_string(time_proposed.at(i))+"\n";
	}
	file.close();
    
    file.open("./results/proposed/Data/testAccVer_result"+ index +".csv");
    file << "N,Time taken\n";
	cout << "\n/*-----------------Accumulator verification time------------------------------------*/" << endl;
	for(size_t i = 0; i < len; i++) {
		cout << "\n/*-----------Number of elements: " << (i+1)*step << " -----------------*/" << endl;
		cout << "NI-PoE verification time for the proposed  " << time_verify_proposed.at(i) << " seconds" << endl;
        file << to_string((i+1)*step)+","+to_string(time_verify_proposed.at(i))+"\n";
	}
 }

}  // namespace testproposed
