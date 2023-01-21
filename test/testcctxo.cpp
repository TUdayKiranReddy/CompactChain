#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
//#include <bits/stdc++.h>
#include <math.h>

#include <algorithms/RSAAccumulator.hpp>
#include <algorithms/RSAKey.hpp>
#include <algorithms/MerkleAccumulator.hpp>
#include <algorithms/MMRTree.hpp>

#include <utils/Pointers.hpp>
#include <utils/Profiler.hpp>
#include <utils/SHA256.hpp>
#include <utils/ThreadPool.hpp>

#include <flint/BigInt.hpp>
#include <flint/BigMod.hpp>
#include <flint/Random.hpp>

using namespace std;

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


int main(){
	int setSize = 1000000;
// CompactChain's tx validity performance
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
  
    int size = 200;
    vector<flint::BigInt> e_1;
    for(size_t i = 0; i < size; i++)
		e_1.push_back(elements[i]);


	flint::BigMod prev_acc;
	prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
	prev_acc = rsaKey.getPublicKey().base;
	flint::BigMod prev_acc_stxo(prev_acc), prev_acc_txo(prev_acc);
	vector<double> time_proposed, time_proposed_nonmem, time_proposed_mem;
	vector<double> time_proposed_batch, time_proposed_batch_nonmem, time_proposed_batch_mem;

	double compact_avg = 0.0, compact_avg_mem = 0.0, compact_avg_nonmem = 0.0;
	double compact_avg_batch = 0.0, compact_avg_batch_mem = 0.0, compact_avg_batch_nonmem = 0.0;

	int len = 125;
	int Ntx = 8;

	vector<flint::BigInt> elements_TXO, elements_STXO;
	flint::BigMod TXO_C, STXO_C, A, Q_TXO, Q_STXO, Q_A, d, w;
	flint::BigInt b;
	vector<future<void>> futures;
    int itr=0;

	size_t j;
	for(j = 0; j < 1000; j++){
		elements_STXO.push_back(elements[j]);
		//cout << j << endl;
		
		elements_TXO.push_back(elements[j+1000]);
		//cout << j+1000 << endl;
	}

	vector<flint::BigInt> rep_STXO(elements_STXO.size()), rep_TXO(elements_TXO.size());


	futures.push_back(threadPool.enqueue<void>([&, itr]() {
            RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator), rep_STXO, threadPool);
        }));
    itr++;
    futures.push_back(threadPool.enqueue<void>([&, itr]() {
            RSAAccumulator::genRepresentatives(elements_TXO, *(rsaKey.getPublicKey().primeRepGenerator), rep_TXO, threadPool);
        }));
    
    for(auto& future : futures) {
        future.get();
    }
    itr = 0;
    futures.clear();
    futures.push_back(threadPool.enqueue<void>([&, itr]() {
            RSAAccumulator::batchAdd(rep_TXO, rsaKey, prev_acc_stxo, TXO_C, Q_TXO);
        }));
    itr++;
    futures.push_back(threadPool.enqueue<void>([&, itr]() {
            RSAAccumulator::batchAdd(rep_STXO, rsaKey, prev_acc_txo, STXO_C, Q_STXO);
        }));
    
    for(auto& future : futures) {
        future.get();
    }
	itr=0;
	futures.clear();	
	/*-----------------------Single Transaction proof-------------------------------------*/
	vector<flint::BigMod> W(elements_TXO.size());
	flint::BigInt x_stxo = elements_TXO[0], x_txo = elements_TXO[0];
	futures.push_back(threadPool.enqueue<void>([&, itr]() {
		RSAAccumulator::witnessesForSet(rep_TXO, rsaKey, W, threadPool);
	}));
	itr++;
	futures.push_back(threadPool.enqueue<void>([&, itr]() {
		RSAAccumulator::CreateNonMemWit(x_stxo, rep_STXO, rsaKey, prev_acc_stxo, d, b);
	}));
	for(auto& future:futures)
		future.get();
	itr = 0;
	futures.clear();
	/*-----------------------1000 Transactions proof-------------------------------------*/
	vector<vector<flint::BigMod>> Wit(Ntx);
	for(int y=0;y<Ntx;y++)
		Wit[y].resize(elements_TXO.size());
	
	vector<flint::BigInt> X_stxo, X_txo;
	for(int y=0;y<Ntx;y++){
		X_stxo.push_back(elements_STXO[y]);
		X_txo.push_back(elements_TXO[y]);
	}
	vector<flint::BigMod> D(Ntx);
	vector<flint::BigInt> B(Ntx);

	for(int p=0;p<Ntx;p++){
		futures.push_back(threadPool.enqueue<void>([&, p]() {
			RSAAccumulator::witnessesForSet(rep_TXO, rsaKey, Wit.at(p), threadPool);
		}));
	}
	for(int p=0;p<Ntx;p++){
		futures.push_back(threadPool.enqueue<void>([&, p]() {
			RSAAccumulator::CreateNonMemWit(X_stxo.at(p), rep_STXO, rsaKey, prev_acc_stxo, D.at(p), B.at(p));
		}));
	}
	for(auto& future:futures)
		future.get();

	int avr_itr = 10;
	
	for(int i=0;i<avr_itr*len;i++){
		cout << "Iteration:- " << i << endl;
		itr=0;
		futures.clear();
		bool b1, b2;
		cout << "/*----------------------- Single Transaction verify-------------------------------------*/\n";
		double Start = Profiler::getCurrentTime();
             futures.push_back(threadPool.enqueue<void>([&, itr](){
                 RSAAccumulator::VerifyNonMemWit(x_stxo, rsaKey, STXO_C, prev_acc_stxo, d, b, b1);    
             }));
    		itr++;
            futures.push_back(threadPool.enqueue<void>([&, itr](){
    		  RSAAccumulator::verify(x_txo, W[0], TXO_C, rsaKey.getPublicKey(), b2);
            }));
            for(auto& future:futures)
                future.get();
        double End = Profiler::getCurrentTime();
		time_proposed.push_back(End - Start);
	
		Start = Profiler::getCurrentTime();
        RSAAccumulator::VerifyNonMemWit(x_stxo, rsaKey, STXO_C, prev_acc_stxo, d, b, b1);    
        double nonmemEnd = Profiler::getCurrentTime();
		RSAAccumulator::verify(x_txo, W[0], TXO_C, rsaKey.getPublicKey(), b2);
        End = Profiler::getCurrentTime();
		time_proposed_nonmem.push_back(nonmemEnd - Start);
		time_proposed_mem.push_back(End - nonmemEnd);

		itr=0;
		futures.clear();
		cout << "\nTime consumed to verify a transaction in CompactChain: " << time_proposed[i] << endl;
		if(b1)
			cout << "Non-Membership Witness in STXO verified!" << endl;
		else
			cout << "Non-Membership Witness in STXO not verified!!" << endl;
		cout << "Time consumed to verify Non-Membership Witness in CompactChain: " << time_proposed_nonmem[i] << endl;

		if(b2)
			cout << "Membership Witness in TXO verified!" << endl;
		else
			cout << "Membership Witness in TXO not verified!!" << endl;
		cout << "Time consumed to verify Membership Witness in CompactChain: " << time_proposed_mem[i] << endl;

		bool b1s, b2s;

		cout << "/*----------------------- 1000 Transactions verify-------------------------------------*/\n";
		Start = Profiler::getCurrentTime();
			for(int p=0;p<Ntx;p++){
				futures.push_back(threadPool.enqueue<void>([&, p](){
					RSAAccumulator::VerifyNonMemWit(X_stxo.at(p), rsaKey, STXO_C, prev_acc_stxo, D.at(p), B.at(p), b1s);    
				}));
	    	}
	    	for(int p=0;p<Ntx;p++){
	            futures.push_back(threadPool.enqueue<void>([&, p](){
	    			RSAAccumulator::verify(X_txo.at(p), (Wit[p]).at(p), TXO_C, rsaKey.getPublicKey(), b2s);
	            }));
	        }
            for(auto& future:futures)
                future.get();
        End = Profiler::getCurrentTime();
		time_proposed_batch.push_back(End - Start);
	
		Start = Profiler::getCurrentTime();
			for(int p=0;p<Ntx;p++)
        		RSAAccumulator::VerifyNonMemWit(X_stxo.at(p), rsaKey, STXO_C, prev_acc_stxo, D.at(p), B.at(p), b1s);    
        nonmemEnd = Profiler::getCurrentTime();
        	for(int p=0;p<Ntx;p++)
				RSAAccumulator::verify(X_txo.at(p), (Wit[p]).at(p), TXO_C, rsaKey.getPublicKey(), b2s);
        End = Profiler::getCurrentTime();
		time_proposed_batch_nonmem.push_back(nonmemEnd - Start);
		time_proposed_batch_mem.push_back(End - nonmemEnd);

		itr=0;
		futures.clear();
		cout << "\nTime consumed to verify a transaction in CompactChain: " << time_proposed_batch[i] << endl;
		if(b1)
			cout << "Non-Membership Witness in STXO verified!" << endl;
		else
			cout << "Non-Membership Witness in STXO not verified!!" << endl;
		cout << "Time consumed to verify Non-Membership Witness in CompactChain: " << time_proposed_batch_nonmem[i] << endl;

		if(b2)
			cout << "Membership Witness in TXO verified!" << endl;
		else
			cout << "Membership Witness in TXO not verified!!" << endl;
		cout << "Time consumed to verify Membership Witness in CompactChain: " << time_proposed_batch_mem[i] << endl;


		for(size_t j = 0; j < (i+1); ++j){
			compact_avg += time_proposed[j];
			compact_avg_nonmem += time_proposed_nonmem[j];
			compact_avg_mem += time_proposed_mem[j];

			compact_avg_batch += time_proposed_batch[j];
			compact_avg_batch_nonmem += time_proposed_batch_nonmem[j];
			compact_avg_batch_mem += time_proposed_batch_mem[j];
		}
		
		cout << "\nAverage Time consumed to verify a transaction in CompactChain: " << compact_avg/(i+1) << endl;
		cout << "Average Time consumed to verify a Non-Mem Wit in CompactChain: " << compact_avg_nonmem/(i+1) << endl;
		cout << "Average Time consumed to verify a Mem Wit in CompactChain: " << compact_avg_mem/(i+1) << endl;

		cout << "\nAverage Time consumed to verify a transactions(parallel) in CompactChain: " << compact_avg_batch/(i+1) << endl;
		cout << "Average Time consumed to verify a Non-Mem Wit in CompactChain: " << compact_avg_batch_nonmem/(i+1) << endl;
		cout << "Average Time consumed to verify a Mem Wit in CompactChain: " << compact_avg_batch_mem/(i+1) << endl;
		cout <<endl;
	}
	compact_avg = 0.0, compact_avg_mem = 0.0, compact_avg_nonmem = 0.0;
	compact_avg_batch = 0.0, compact_avg_batch_mem = 0.0, compact_avg_batch_nonmem = 0.0;
	for(size_t i = 0; i < avr_itr*len; ++i){
		compact_avg += time_proposed[i];
		compact_avg_nonmem += time_proposed_nonmem[i];
		compact_avg_mem += time_proposed_mem[i];

		compact_avg_batch += time_proposed_batch[i];
		compact_avg_batch_nonmem += time_proposed_batch_nonmem[i];
		compact_avg_batch_mem += time_proposed_batch_mem[i];
	}

	compact_avg /= (avr_itr*len);
	compact_avg_nonmem /= (avr_itr*len);
	compact_avg_mem /= (avr_itr*len);
	// compact_avg_batch /= len;
	// compact_avg_batch_nonmem /= len;
	// compact_avg_batch_mem /= len;
	compact_avg_batch /= avr_itr;
	compact_avg_batch_nonmem /= avr_itr;
	compact_avg_batch_mem /= avr_itr;

	std::ofstream file;
    file.open("./results/proposed/FinalTXOVerification.csv");
    file << "Parallel, Non-Mem, Mem\n";
	cout << "\n/*-------------------------Average Single Transaction Verification time over "<< len << " Iterations------------------------------*/\n";
	cout << "Average Time consumed to verify a transaction in CompactChain: " << compact_avg << endl;
	cout << "Average Time consumed to verify a Non-Mem Wit in CompactChain: " << compact_avg_nonmem << endl;
	cout << "Average Time consumed to verify a Mem Wit in CompactChain: " << compact_avg_mem << endl;
	file << compact_avg << "," << compact_avg_nonmem << "," << compact_avg_mem << "\n\n";

    cout << "\n/*-------------------------Average " << Ntx <<  " Transactions Verification time over "<< len << " Iterations----------------*/\n";
    cout << "\nAverage Time consumed to verify a transactions(parallel) in CompactChain: " << compact_avg_batch << endl;
    cout << "Average Time consumed to verify a Non-Mem Wit in CompactChain: " << compact_avg_batch_nonmem << endl;
    cout << "Average Time consumed to verify a Mem Wit in CompactChain: " << compact_avg_batch_mem << endl;
    file << compact_avg_batch << "," << compact_avg_batch_nonmem << "," << compact_avg_batch_mem << "\n";
    file.close();
	
}