#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
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

namespace proposed{
	void test();
	vector<flint::BigInt> readBigInts(string filename);
}

int main(int argc, char** argv) {
    proposed::test();
    return 0;
}


namespace proposed{

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

	void test(){
		static const int THREAD_POOL_SIZE=16;
		static const int STXO_SIZE = 1000, TXO_SIZE = 1000;
		static const int RSA_KEY_SIZE = 3072;//bits

		// ThreadPool for Multithreading
		ThreadPool threadPool(THREAD_POOL_SIZE);

		// Generating Random Numbers for STXO and TXO set
		vector<flint::BigInt> stxo_elements, txo_elements;
		stxo_elements = readBigInts("randomBigInts" + to_string(STXO_SIZE));
		txo_elements = readBigInts("randomBigInts" + to_string(TXO_SIZE));

		// Generating RSA public/private Key
		RSAKey rsaKey;
    	RSAAccumulator::genKey(0, RSA_KEY_SIZE, rsaKey);

    	//Generating Representatives for stxo and txo set elements
    	cout << "\n/*---------Generate representatives for the elements-----------------*/" << endl;
    	vector<future<void>> futures;
    	vector<flint::BigInt> stxo_rep(STXO_SIZE), txo_rep(TXO_SIZE);
    	vector<flint::BigMod>::size_type element = 0;
    	double genrepStart = Profiler::getCurrentTime();

    	futures.push_back(threadPool.enqueue<void>([&, element]() {
                RSAAccumulator::genRepresentatives(stxo_elements, *(rsaKey.getPublicKey().primeRepGenerator), stxo_rep, threadPool);
            }));
    	element++;
    	futures.push_back(threadPool.enqueue<void>([&, element]() {
                RSAAccumulator::genRepresentatives(txo_elements, *(rsaKey.getPublicKey().primeRepGenerator), txo_rep, threadPool);
            }));
    	for(auto& future : futures) {
            future.get();
        }
    	double genrepEnd = Profiler::getCurrentTime();
    	cout << "Generated " << STXO_SIZE << " STXO elements & " << TXO_SIZE << " TXO elements prime representatives in " << genrepEnd - genrepStart << " secounds" << endl; 
    	

    	// RSA Accumulation of these sets
    	cout << "\n/*---------RSA Accumulator-----------------*/" << endl;
    	flint::BigMod STXO_C, TXO_C;
    	flint::BigInt stxo_product, txo_product;
    	futures.clear();
    	element = 0;
    	double rsaStart = Profiler::getCurrentTime();
    	futures.push_back(threadPool.enqueue<void>([&, element]() {
	    	RSAAccumulator::accumulateSet(stxo_rep, rsaKey.getPublicKey(), STXO_C, stxo_product);
	    }));
	    element++;
	    futures.push_back(threadPool.enqueue<void>([&, element]() {
	    	RSAAccumulator::accumulateSet(txo_rep, rsaKey.getPublicKey(), TXO_C, txo_product);
	    }));
	    element++;
	    for(auto& future : futures) {
            future.get();
        }
	    double rsaEnd = Profiler::getCurrentTime();
	    cout << "Accumulated " << STXO_SIZE << " STXO elements & " << TXO_SIZE << " TXO elements in " << rsaEnd - rsaStart << " secounds" << endl; 

	    cout << "Total Time for Accumulation " << rsaEnd - genrepStart << " secounds" << endl; 
	    // cout << STXO_C << endl;
	    // cout << TXO_C << endl;
	    cout << "\n/*-------------------------------------------------------------------*/" << endl;


	    
	}
}