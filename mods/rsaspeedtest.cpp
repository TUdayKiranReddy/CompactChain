/*
 * rsaspeedtest.cpp
 *
 *  Created on: Apr 20, 2013
 *      Author: etremel
 */

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
   //  for(auto& element : elements) {
       //  unsigned bits;
       //  x = element;
       //  for(bits = 0; x != 0; ++bits) x >>= 1;
       //  cout << "\n" << element << " " << element.bitLength() << endl;
    // }
   // cout << elements.size() << endl;

    //Generate the public/private key
    double keyGenStart = Profiler::getCurrentTime();
    RSAKey rsaKey;
    RSAAccumulator::genKey(0, 3072, rsaKey);
    double keyGenEnd = Profiler::getCurrentTime();
    cout << "Key generation took " << (keyGenEnd-keyGenStart) << " seconds" << endl;
    //cout << (keyGenEnd - keyGenStart) << endl;
    //cout << rsaKey.getPublicKey().rsaModulus << endl;
    //cout << rsaKey.getPublicKey().rsaModulus.bitLength() << endl;
    //cout << rsaKey.getPublicKey().base << endl;
    //cout << rsaKey.getPublicKey().base.bitLength() << endl;
    //cout << rsaKey.getSecretKey().p << endl;
    //cout << rsaKey.getSecretKey().q << endl;
    //flint::BigInt N;
    //N = (rsaKey.getSecretKey().p - 1) * (rsaKey.getSecretKey().q - 1);
    //cout << N << endl;
    //cout << (N == rsaKey.getPublicKey().rsaModulus) << endl;

	cout << "\n/*---------Generate representatives for the elements-----------------*/" << endl;
    //Generate representatives for the elements
    int size = 1000;
    vector<flint::BigInt> e_1;
    for(size_t i = 0; i < size; i++)
		e_1.push_back(elements[i]);
		
    vector<flint::BigInt> representatives(size);
    double repGenStart = Profiler::getCurrentTime();
    RSAAccumulator::genRepresentatives(e_1, *(rsaKey.getPublicKey().primeRepGenerator),
                                       representatives, threadPool);
    double repGenEnd = Profiler::getCurrentTime();
    cout << "Generated " << representatives.size() << " prime representatives in " << (repGenEnd-repGenStart) << " seconds" << endl;
   // cout << (repGenEnd - repGenStart) << endl;
     //for(auto& rep : representatives) {
        //// unsigned bits;
        //// x = element;
        //// for(bits = 0; x != 0; ++bits) x >>= 1;
         //cout << "\n" << rep << " " << rep.bitLength() << " "<< sizeof(rep) << endl;
     //}

    //flint::BigInt product = 1;
    //for(size_t i = 0; i < representatives.size(); i++) {
       //// output ^= reps.at(i);
        //product *= representatives.at(i);
    //}

	//cout << product << endl;
	
	cout << "\n/*---------Accumulate with private key-----------------*/" << endl;
    //Accumulate the representatives
    flint::BigMod accumulator;
    double accStart = Profiler::getCurrentTime();
    RSAAccumulator::accumulateSet(representatives, rsaKey, accumulator, threadPool);
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
    double Start = Profiler::getCurrentTime();
    RSAAccumulator::batchAdd(e_1, rsaKey, threadPool, prev_acc, acc, Q);
    double End = Profiler::getCurrentTime();
    cout << "Accumulated " << representatives.size() << " prime representatives in " << (End-Start) << " seconds with public key" << endl;
    cout << acc << endl;
    if(accumulator == acc) 
        cout << "\nAccumulator generated through Public and private information does match!" << endl;
    cout << "\nNI-PoE Proof:" << Q << endl;
    
    double StartVerify = Profiler::getCurrentTime();
    bool b = RSAAccumulator::NIPoE_Verify(e_1, threadPool, rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, acc, Q);
    double EndVerify = Profiler::getCurrentTime();
    if(b == 1)
		cout << "NI-PoE proof for the commitment is verified successfully" << endl;
	else
		cout << "NI-PoE proof verification failed" << endl;
    cout << "NI-PoE verification time for 1000 elements:" << (EndVerify - StartVerify) << " seconds" << endl;

    //cout << "\n/*---------Gennerate witnesses for all elements-----------------*/" << endl;
    //////Generate witnesses for all of the representatives
    ////vector<flint::BigMod> witnesses(size);
    ////double witStart = Profiler::getCurrentTime();
    ////RSAAccumulator::witnessesForSet(representatives, rsaKey, witnesses, threadPool);
    ////double witEnd = Profiler::getCurrentTime();
    ////cout << "Generated " << witnesses.size() << " witnesses in " << (witEnd-witStart) << " seconds with private key" << endl;
   ////// cout << (witEnd - witStart) << endl;

    
    ////Generate witnesses again with only the public information
    //vector<flint::BigMod> witnessesPub(size);
    //double witPubStart = Profiler::getCurrentTime();
    //RSAAccumulator::witnessesForSet(representatives, rsaKey.getPublicKey(), witnessesPub, threadPool);
    //double witPubEnd = Profiler::getCurrentTime();
    //cout << "Generated " << witnessesPub.size() << " witnesses in " << (witPubEnd-witPubStart) << " seconds with public key" << endl;
   //// cout << (witPubEnd - witPubStart) << endl;

	//cout << "\n/*---------Verify the values with the witnesses-----------------*/" << endl;
    ////////Verify the values with the witnesses
    //////double verifyStart = Profiler::getCurrentTime();
    //////for(size_t i = 0; i < elements.size(); i++) {
        //////bool verifyPassed = RSAAccumulator::verify(elements.at(i), witnesses.at(i), accumulator, rsaKey.getPublicKey());
        //////if(!verifyPassed) {
            //////cout << "Witness for element " << i << " did not pass!" << endl;
        //////}
    //////}
   ////// double verifyEnd = Profiler::getCurrentTime();
   ////// cout << "Verified " << elements.size() << " elements in " << (verifyEnd-verifyStart) << " seconds" << endl;
   ////// cout << (verifyEnd - verifyStart) << endl;

    ////Verify the public-key witnesses, just in case they're different
    //double verifyPubStart = Profiler::getCurrentTime();
    //for(size_t i = 0; i < e_1.size(); i++) {
        //bool verifyPassed = RSAAccumulator::verify(e_1.at(i), witnessesPub.at(i), accPub, rsaKey.getPublicKey());
        //if(!verifyPassed) {
            //cout << "Witness for element " << i << " did not pass!" << endl;
        //}
    //}
    
  //// vector<bool> b;
  //// RSAAccumulator::Verify(e_1, witnessesPub, accPub, rsaKey.getPublicKey(), threadPool, b);
   //double verifyPubEnd = Profiler::getCurrentTime();
   //cout << "Verified " << witnessesPub.size() << " elements in " << (verifyPubEnd-verifyPubStart) << " seconds against public accumulator" << endl;
    ////This actually doesn't need to get measured and logged, since the time will
    ////be the same as for verification with the private-key witnesses. It only
    ////needs to run to guarantee correctness.
    
    //cout << "\n/*---------Accumulate 1000 more elements to the previous computed accumulator-----------------*/" << endl;
    //vector<flint::BigInt> e_2;
    //for(size_t i = 0; i < size; i++)
		//e_2.push_back(elements[i+1000]);
		
	//// Batch Addition and NI-PoE 
    //prev_acc = acc;
	////flint::BigMod acc, Q;
    //Start = Profiler::getCurrentTime();
    //RSAAccumulator::batchAdd(e_2, rsaKey, threadPool, prev_acc, acc, Q);
    //End = Profiler::getCurrentTime();
    //cout << "Accumulated " << representatives.size() << " prime representatives in " << (End-Start) << " seconds with public key" << endl;
    //cout << acc << endl;
    //if(accumulator == acc) 
        //cout << "\nAccumulator generated through Public and private information does match!" << endl;
    //cout << "\nNI-PoE Proof:" << Q << endl;
    
    //StartVerify = Profiler::getCurrentTime();
    //b = RSAAccumulator::NIPoE_Verify(e_2, threadPool, rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, acc, Q);
    //EndVerify = Profiler::getCurrentTime();
    //if(b == 1)
		//cout << "NI-PoE proof for the commitment is verified successfully" << endl;
	//else
		//cout << "NI-PoE proof verification failed" << endl;
    //cout << "NI-PoE verification time for 1000 elements:" << (EndVerify - StartVerify) << " seconds" << endl;
    
    //if(prev_acc != acc)
		//cout << "Accumulator updated" << endl;
		//cout << "New Accumulator:" << acc;

	//cout << "\n/*---------Update Memebership Witness-----------------*/" << endl;
	//flint::BigMod upwit;
////	vector<flint::BigInt> rep(size);
////	RSAAccumulator::genRepresentatives(e_2, *(rsaKey.getPublicKey().primeRepGenerator), rep, threadPool);
    //double StartWitUp = Profiler::getCurrentTime();                                 
	//RSAAccumulator::UpMemWit(e_2, rsaKey, threadPool, witnessesPub.at(0));
	//double EndWitUp = Profiler::getCurrentTime();
	//cout << "Witness Updated in " << (EndWitUp - StartWitUp) << " seconds" << endl;
	//upwit = witnessesPub.at(0);
	//upwit ^= representatives.at(0);
	//if(acc == upwit)
		//cout << "Witness updated successfully" << endl;
	//else
		//cout << "Witness update failed" << endl;


	/*--------------------------Simulation Accumulator update----------------*/
	cout << "/*----------------Simulation for Accumulator update-----------------------------*/" << endl;
	//flint::BigMod prev_acc;
	prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
	prev_acc = rsaKey.getPublicKey().base;
	vector<double> time_minichain, time_proposed, time_verify_minichain, time_verify_proposed;
	for(size_t i = 0; i < 10; ++i) {
		vector<flint::BigInt> elements_TXO, elements_STXO;
		flint::BigMod TXO_C, STXO_C, A, Q_TXO, Q_STXO, Q_A;
	//	prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
	//	prev_acc = rsaKey.getPublicKey().base;
		for(size_t j = 0; j < (i+1)*100; j++){
			elements_STXO.push_back(elements[j]);
			//cout << j << endl;
			
			elements_TXO.push_back(elements[j+1000]);
			//cout << j+1000 << endl;
		}
		
		// Minichain's accumulator update
		double Start = Profiler::getCurrentTime();
		RSAAccumulator::batchAdd(elements_STXO, rsaKey, threadPool, prev_acc, A, Q_A);
		double End = Profiler::getCurrentTime();
		time_minichain.push_back(End - Start);
		//cout << "Minichain's time" << (End - Start) << endl;
		
		// Proposed stateless blockchain's accumulator update
		Start = Profiler::getCurrentTime();
		RSAAccumulator::batchAdd(elements_TXO, rsaKey, threadPool, prev_acc, TXO_C, Q_TXO);
		RSAAccumulator::batchAdd(elements_STXO, rsaKey, threadPool, prev_acc, STXO_C, Q_STXO);
		End = Profiler::getCurrentTime();
		time_proposed.push_back(End - Start);
	//	cout << "proposed protocol's time" << (End - Start) << endl;
		
		double StartVerify = Profiler::getCurrentTime();
		bool b = RSAAccumulator::NIPoE_Verify(elements_STXO, threadPool, rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, A, Q_A);
		double EndVerify = Profiler::getCurrentTime();
		time_verify_minichain.push_back(EndVerify - StartVerify);
		if(b == 1)
			cout << "NI-PoE proof for the minichain's STXO_C  is verified successfully" << endl;
		else
			cout << "NI-PoE proof verification for the minichain's STXO_C failed" << endl;
		
		StartVerify = Profiler::getCurrentTime();
		bool b_TXO = RSAAccumulator::NIPoE_Verify(elements_TXO, threadPool, rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, TXO_C, Q_TXO);
		bool b_STXO = RSAAccumulator::NIPoE_Verify(elements_STXO, threadPool, rsaKey, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, STXO_C, Q_STXO);
		EndVerify = Profiler::getCurrentTime();
		time_verify_proposed.push_back(EndVerify - StartVerify);
		if(b_TXO == 1)
			cout << "NI-PoE proof for the proposed protocol's TXO_C  is verified successfully" << endl;
		else
			cout << "NI-PoE proof verification for the proposed protocol's TXO_C failed" << endl;
		
		if(b_TXO == 1)
			cout << "NI-PoE proof for the proposed protocol's STXO_C  is verified successfully" << endl;
		else
			cout << "NI-PoE proof verification for the proposed protocol's STXO_C failed" << endl;
		
	}
	cout << "\n/*-----------------Accumulator Update time-----------------------------*/" << endl;
	for(size_t i = 0; i < 10; ++i) {
		cout << "\n/*-----------Numeber of elements: " << (i+1)*100 << " -----------------*/" << endl;
		cout << "Minichain accumulator update time: " << time_minichain.at(i) << " seconds"  << endl;
		cout << "Proposed accumulator update time : " << time_proposed.at(i) << " seconds" << endl;
	}
	
	cout << "\n/*-----------------Accumulator verification time------------------------------------*/" << endl;
	for(size_t i = 0; i < 10; ++i) {
		cout << "\n/*-----------Numeber of elements: " << (i+1)*100 << " -----------------*/" << endl;
		cout << "NI-PoE verification time for the minichain " << time_verify_minichain.at(i) << " seconds" << endl;
		cout << "NI-PoE verification time for the proposed  " << time_verify_proposed.at(i) << " seconds" << endl;
	}
 }

}  // namespace speedtest
