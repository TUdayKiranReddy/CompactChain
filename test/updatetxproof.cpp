
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
void updatetxWit(int setSize, string index);
vector<flint::BigInt> readBigInts(string filename);
}  // namespace speedtest

int main(int argc, char** argv) {
    int setSize;
    if(argc > 1) {
        setSize = atoi(argv[1]);
    } else {
        setSize = 20000;
    }
    speedtest::updatetxWit(setSize, argv[2]);
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

void updatetxWit(int setSize, string index) {
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

    int size = 1000;
    vector<flint::BigInt> e_1;
    for(size_t i = 0; i < size; i++)
		e_1.push_back(elements[i]);
    
	cout << "\n/*---------Accumulate again with only the public information-----------------*/" << endl;
    flint::BigMod prev_acc;
	prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
	prev_acc = rsaKey.getPublicKey().base;
    flint::BigMod acc, Q;
    std::vector<flint::BigInt> reps(size);
    
    double Start = Profiler::getCurrentTime();
    RSAAccumulator::genRepresentatives(e_1, *(rsaKey.getPublicKey().primeRepGenerator),
                                       reps, threadPool);
    RSAAccumulator::batchAdd(reps, rsaKey, prev_acc, acc, Q);
    double End = Profiler::getCurrentTime();
    cout << "Accumulated " << reps.size() << " prime representatives in " << (End-Start) << " seconds with public key" << endl;
 
    
    cout << "\n/*---------Generate witnesses for all elements-----------------*/" << endl;
    //Generate witnesses for all of the representatives
    vector<flint::BigMod> witnesses(size);
    double witStart = Profiler::getCurrentTime();
    RSAAccumulator::witnessesForSet(reps, rsaKey, witnesses, threadPool);
    double witEnd = Profiler::getCurrentTime();
    cout << "Generated " << witnesses.size() << " witnesses in " << (witEnd-witStart) << " seconds with private key" << endl;
 
   /*-----------------------Membership verification----------------*/
    flint::BigInt x_m = elements[100];
    flint::BigMod w_m = witnesses[100];
    bool verifyPassed;
    RSAAccumulator::verify(x_m, w_m, acc, rsaKey.getPublicKey(), verifyPassed);
        if(verifyPassed) {
            cout << "\nMembership Witness verified!" << endl;
        }
        else 
			cout << "\nMembership Witness  not verified!" << endl;

    /*-------------------Non Membership verification------------------*/
    flint::BigInt x_k = elements[2500];
    flint::BigMod d;
    flint::BigInt b;

    RSAAccumulator::CreateNonMemWit(x_k, reps, rsaKey, prev_acc, d, b);
    bool ans;
    RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, acc, prev_acc, d, b, ans);
    
    if(ans)
        cout << "\nNon-Membership Witness verified!" << endl;
    else
        cout << "\nNon-Membership Witness not verified!!" << endl;
        
   /*--------------NonMemWit update----------------------------------------------*/
   flint::BigMod new_d;
   flint::BigInt new_b;
   vector<flint::BigInt> e_2;
   for(size_t i = 0; i < size; i++)
		e_2.push_back(elements[i+1000]);
		
   x_k = elements[2500];
   std::vector<flint::BigInt> reps_e2(size);
   RSAAccumulator::genRepresentatives(e_2, *(rsaKey.getPublicKey().primeRepGenerator),
                                       reps_e2, threadPool);
   RSAAccumulator::UpNonMemWit(x_k, d, b, reps_e2, rsaKey, acc, new_d, new_b); 
   
	prev_acc = acc;
	//flint::BigMod acc, Q;
    RSAAccumulator::batchAdd(reps_e2, rsaKey, prev_acc, acc, Q);
    prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
	prev_acc = rsaKey.getPublicKey().base;
    RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, acc, prev_acc, new_d, new_b, ans);
    
    if(ans)
        cout << "\nThe updated Non-Membership Witness verified!" << endl;
    else
        cout << "\nThe updated Non-Membership Witness not verified!!" << endl;
        
    /*------------------Update membership witness-------------------*/
    RSAAccumulator::UpMemWit(e_2, rsaKey, threadPool, w_m);
    RSAAccumulator::verify(x_m, w_m, acc, rsaKey.getPublicKey(), verifyPassed);
        if(verifyPassed) {
            cout << "\nThe updated Membership Witness verified!" << endl;
        }
        else 
			cout << "\nThe updated Membership Witness  not verified!" << endl;
			
	int step = 200;
	int len = 5;
        
	/*-----------------Witness update simulations---------------------------*/
	vector<double> mc_update_time, cc_update_time;
	for(size_t i = 0; i < len; ++i) {
		prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
		prev_acc = rsaKey.getPublicKey().base;

		cout << "\n/*-------------Iteration " << i+1 << " --------------*/" << endl;
		vector<flint::BigInt> elements_TXO, elements_STXO;
		flint::BigMod TXO_C, STXO_C, A, Q_TXO, Q_STXO, Q_A;

	    size_t TXOsize = step*(i+1);
	    size_t STXOsize = step*(i+1);

		for(size_t j = i*size; j < (i+1)*size; j++){
			elements_STXO.push_back(elements[j]);
			elements_TXO.push_back(elements[j+1000]);
		}
		vector<future<void>> futures;
        vector<flint::BigMod>::size_type itr = 0;

		std::vector<flint::BigInt> rep_A(elements_STXO.size()), rep_STXO(elements_STXO.size()), rep_TXO(elements_TXO.size());
		// Minichain's witness update
		//double Start = Profiler::getCurrentTime();
		RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_A, threadPool);
		RSAAccumulator::batchAdd(rep_A, rsaKey, prev_acc, A, Q_A);
		//double End = Profiler::getCurrentTime();
		//time_minichain.push_back(End - Start);
		flint::BigInt x_k = elements[20000];
		flint::BigMod d;
		flint::BigInt b;

		RSAAccumulator::CreateNonMemWit(x_k, rep_A, rsaKey, prev_acc, d, b);
		//bool ans;
		//RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, acc, prev_acc, d, b, ans);
		
		vector<flint::BigInt> e;
		for(size_t k = 0; k < STXOsize; k++)
			e.push_back(elements[k+10000]);

		//x_k = elements[2500];
		std::vector<flint::BigInt> reps_e(STXOsize);
		
		double updateStart = Profiler::getCurrentTime();
			RSAAccumulator::genRepresentatives(e, *(rsaKey.getPublicKey().primeRepGenerator),
	                                       reps_e, threadPool);	

			futures.push_back(threadPool.enqueue<void>([&, itr]() {
				RSAAccumulator::UpNonMemWit(x_k, d, b, reps_e, rsaKey, A, new_d, new_b); 
			}));
			for(auto& future:futures)
				future.get();
		double updateEnd = Profiler::getCurrentTime();
		mc_update_time.push_back(updateEnd - updateStart);
		cout << "\nTime consumed to update tx witness in MiniChain " << mc_update_time[i] << endl;
		itr=0;
		futures.clear();
		prev_acc = A;
		//flint::BigMod acc, Q;
		RSAAccumulator::batchAdd(reps_e, rsaKey, prev_acc, A, Q);
		prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
		prev_acc = rsaKey.getPublicKey().base;
		RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, A, prev_acc, new_d, new_b, ans);
    
		if(ans)
			cout << "\nThe updated Witness in minichain verified successfully!" << endl;
		else
			cout << "\nThe updated Witness in minichain not verified!!" << endl;

		
		// Proposed stateless blockchain's tx witness update
	//	Start = Profiler::getCurrentTime();
		RSAAccumulator::genRepresentatives(elements_TXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_TXO, threadPool);
		RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_STXO, threadPool);
		RSAAccumulator::batchAdd(rep_TXO, rsaKey, prev_acc, TXO_C, Q_TXO);
		RSAAccumulator::batchAdd(rep_STXO, rsaKey, prev_acc, STXO_C, Q_STXO);
	//	End = Profiler::getCurrentTime();
	//	time_proposed.push_back(End - Start);
		
		vector<flint::BigMod> W(elements_TXO.size());
		RSAAccumulator::witnessesForSet(rep_TXO, rsaKey, W, threadPool);
		
		flint::BigInt x_m = elements_TXO[0];
		flint::BigMod w_m = W[0];
		
		vector<flint::BigInt> e_txo, e_stxo;
		for(size_t k = 0; k < TXOsize; k++){
			e_txo.push_back(elements[k+15000]);
		}

		for(size_t k=0; k < STXOsize; k++){
			e_stxo.push_back(elements[k+10000]);
		}
		itr=0;
		futures.clear();
		std::vector<flint::BigInt> reps_e_txo(TXOsize), reps_e_stxo(STXOsize);
		
		updateStart = Profiler::getCurrentTime();
			futures.push_back(threadPool.enqueue<void>([&, itr]() {
				RSAAccumulator::genRepresentatives(e_txo, *(rsaKey.getPublicKey().primeRepGenerator),
	        	                               reps_e_txo, threadPool);
			}));
			itr++;
			futures.push_back(threadPool.enqueue<void>([&, itr]() {
				RSAAccumulator::genRepresentatives(e_stxo, *(rsaKey.getPublicKey().primeRepGenerator),
	            	                           reps_e_stxo, threadPool);
			}));
			for(auto& future:futures)
	    		future.get();
	    	itr=0;
	    	futures.clear();
			futures.push_back(threadPool.enqueue<void>([&, itr]() {
				RSAAccumulator::UpMemWit(e_txo, rsaKey, threadPool, w_m);
			}));
			itr++;
			futures.push_back(threadPool.enqueue<void>([&, itr]() {
	        	RSAAccumulator::UpNonMemWit(x_k, d, b, reps_e_stxo, rsaKey, STXO_C, new_d, new_b);
	    	}));
	    	for(auto& future:futures)
	    		future.get();
        updateEnd = Profiler::getCurrentTime();
		cc_update_time.push_back(updateEnd - updateStart);
		cout << "\nTime consumed to update tx witness in CompactChain " << cc_update_time[i] << endl; 
        itr=0;
        futures.clear();
		prev_acc = TXO_C;
		RSAAccumulator::batchAdd(reps_e_txo, rsaKey, prev_acc, TXO_C, Q_TXO);
		RSAAccumulator::verify(x_m, w_m, TXO_C, rsaKey.getPublicKey(), verifyPassed);
        	
		prev_acc = STXO_C;
		//flint::BigMod acc, Q;
		RSAAccumulator::batchAdd(reps_e_stxo, rsaKey, prev_acc, STXO_C, Q);
		prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
		prev_acc = rsaKey.getPublicKey().base;
		RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, STXO_C, prev_acc, new_d, new_b, ans);
    
		if(ans + verifyPassed > 1)
			cout << "\nThe updated Witness in compactchain verified successfully!" << endl;
		else
			cout << "\nThe updated Witness in compactchain not verified!!" << endl;
	}
	std::ofstream file, file1;
	file.open("./results/minichain/Data/WitUp" + (index) + ".csv");
	file1.open("./results/proposed/Data/WitUp" + (index) + ".csv");
	file << "N, Time taken\n";
	file1 << "N, Time taken\n";
	cout << "\n/*-----------------------------Transaction Witness Update---------------------------*/\n";
	for(int i=0;i<len;i++){
		cout << "\nTransaction witness update for " << step*(i+1) << endl;
		cout << "Time consumed to update a transaction witness in Minichain: " << mc_update_time[i] << endl;
		cout << "Time consumed to update a transaction witness in CompactChain: " << cc_update_time[i] << endl;
		file << step*(i+1) << "," << mc_update_time[i] << "\n";
		file1 << step*(i+1) << "," << cc_update_time[i] << "\n";
	}
	file.close();
	file1.close();

	
}
}  // namespace speedtest

