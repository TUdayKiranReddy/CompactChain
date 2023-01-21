#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>
#include <math.h>

#include <algorithms/RSAAccumulator.hpp>
#include <algorithms/MerkleAccumulator.hpp>
#include <algorithms/RSAKey.hpp>

#include <utils/Pointers.hpp>
#include <algorithms/MMRTree.hpp>
#include <utils/SHA256.hpp>
#include <utils/Profiler.hpp>
#include <utils/ThreadPool.hpp>
#include <utils/LibConversions.hpp>

#include <flint/BigInt.hpp>
#include <flint/BigMod.hpp>
#include <flint/Random.hpp>

using namespace std;

namespace testAccUp {
void rsaTest(size_t setSize, string index);
vector<flint::BigInt> readBigInts(string filename);
vector<string> readSHA256(string filename);
void string2vv_unsign_char(const vector<string> elements, vector<vector<unsigned char>>& hashes);
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
    testAccUp::rsaTest(setSize, index.str());
    // vector<string> Hhashes = testAccUp::readSHA256("randomSHA2561000");
    // char hashes[256];
    // LibConversions::hexStringToBits(Hhashes[0], hashes);
    // cout << hashes << endl;
    return 0;
}

namespace testAccUp {
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
vector<string> readSHA256(string filename) {
    ifstream fileIn(filename);
    vector<string> elements;
    string fileLine;
    while(getline(fileIn, fileLine)) {
        elements.push_back(move(fileLine));
    }
    return elements;
}

void printVector(vector<unsigned char>& v){
    for(size_t i=0;i<v.size();i++)
        cout << v[i];
    cout <<"\n";
}
void string2vv_unsign_char(const vector<string> elements, vector<vector<unsigned char>>& hashes){
    hashes.resize(elements.size());
    for(size_t i=0;i<elements.size();i++)   
        LibConversions::hexStringToBytes(elements[i], hashes[i]);
}

typedef vector<pair<vector<unsigned char>, bool>> Proof;
void rsaTest(size_t setSize, string index) {
    // cout << "RSA Accumulator test:" << endl;
    static const int THREAD_POOL_SIZE = 8;
    static const int RSA_KEY_SIZE = 3072; //bits
    size_t size = 1000;
    int L = 1000;

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

	
	cout << "\n/*---------Accumulate with private key-----------------*/" << endl;
    //Accumulate the representatives
    flint::BigMod accumulator;
    double accStart = Profiler::getCurrentTime();
    RSAAccumulator::accumulateSetPvt(representatives, rsaKey, accumulator);
    double accEnd = Profiler::getCurrentTime();
    cout << "Accumulated " << representatives.size() << " prime representatives in " << (accEnd-accStart) << " seconds with private key" << endl;
    cout << accumulator << endl;
	
	cout << "\n/*---------Accumulate again with only the public information-----------------*/" << endl;
    //Accumulate again with only the public information
    flint::BigMod accPub;
    flint::BigInt product;
    double pubAccStart = Profiler::getCurrentTime();
    RSAAccumulator::accumulateSet(representatives, rsaKey.getPublicKey(), accPub, product);
    double pubAccEnd = Profiler::getCurrentTime();
    cout << "Accumulated " << representatives.size() << " prime representatives in " << (pubAccEnd-pubAccStart) << " seconds with public key" << endl;
    cout << "accPub: " << accPub << endl;
   

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
    RSAAccumulator::batchAdd(representatives, rsaKey, prev_acc, acc, Q);
    double End = Profiler::getCurrentTime();
    cout << "Accumulated " << representatives.size() << " prime representatives in " << (End-Start) << " seconds with public key" << endl;
    cout << acc << endl;
    if(accumulator == acc) 
        cout << "\nAccumulator generated through Public and private information does match!" << endl;
    cout << "\nNI-PoE Proof:" << Q << endl;
    
    double StartVerify = Profiler::getCurrentTime();
    bool b;
    RSAAccumulator::NIPoE_Verify(rsaKey, representatives, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc, acc, Q, b);
    double EndVerify = Profiler::getCurrentTime();
    if(b == 1)
		cout << "NI-PoE proof for the commitment is verified successfully" << endl;
	else
		cout << "NI-PoE proof verification failed" << endl;
    cout << "NI-PoE verification time for 1000 elements:" << (EndVerify - StartVerify) << " seconds" << endl;
    flint::BigInt x_k = elements[1500];
    flint::BigMod D;
    flint::BigInt B;

    RSAAccumulator::CreateNonMemWit(x_k, representatives, rsaKey, prev_acc, D, B);
    bool ans;
    RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, acc, prev_acc, D, B, ans);
    if (ans)
        cout << "Non Membership Witness verified!\n";
    else{
        cout << "Non Membership Witness not verified!!\n";
    }

	/*--------------------------Simulation Accumulator update----------------*/
	cout << "/*----------------Simulation for Accumulator update-----------------------------*/" << endl;
	//flint::BigMod prev_acc;
	prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
	prev_acc = rsaKey.getPublicKey().base;
	vector<string> Hhashes = readSHA256("randomSHA25610000");
    vector<vector<unsigned char>> hashes;
    string2vv_unsign_char(Hhashes, hashes);

    vector<vector<unsigned char>> E_1;
    for(int i=0;i<L;i++)
        E_1.push_back(hashes[i]);

    MMRTree mmr;
    vector<vector<unsigned char>> prev_peaks;
    mmr.constructTree(E_1, prev_peaks);
    // mmr.printTree();
    flint::BigMod prev_acc_minichain(prev_acc), prev_acc_stxo(prev_acc), prev_acc_txo(prev_acc);

    size_t len = 5;
    int step = 200;
    int MC = 10;
    vector<double> Time_minichain(len, 0.0), Time_proposed(len, 0.0), Time_verify_minichain(len, 0.0), Time_verify_proposed(len, 0.0);
    for(int mc=0;mc<MC;mc++){
        std::cout << "ITERATION:- " << mc << "\n";
        vector<double> time_minichain, time_proposed, time_verify_minichain, time_verify_proposed;
        for(size_t i = 0; i < len; i++) {
            // Setting size of sets
            size_t TXO_SIZE = (i+1)*step;
            size_t STXO_SIZE = (i+1)*step;
        
            vector<flint::BigInt> elements_TXO, elements_STXO;
            flint::BigMod TXO_C, STXO_C, A, Q_TXO, Q_STXO, Q_A;
            vector<flint::BigInt> txo_rep(TXO_SIZE), stxo_rep(STXO_SIZE), rep_a(STXO_SIZE);
            vector<flint::BigInt> txo_rep_V(TXO_SIZE), stxo_rep_V(STXO_SIZE), rep_a_V(STXO_SIZE);
            vector<flint::BigMod>::size_type itr = 0;
            vector<future<void>> futures;

            Proof proof;
            vector<HashNode> MMR_MerkelProof;
            vector<unsigned char> temp_hash; 
            vector<vector<unsigned char>> hashes;
            string elements_strFormat;
            int elements_strFormat_len;

            // Setting Random elements to each Set
            for(size_t j = size; j < size + STXO_SIZE; j++)
                elements_STXO.push_back(elements[j]);

            for(size_t j = size + STXO_SIZE; j < size + STXO_SIZE + TXO_SIZE; j++){
                elements_TXO.push_back(elements[j]);

                //Hashing TXO
                elements_strFormat = elements[j].toHex();
                elements_strFormat_len = elements_strFormat.length();
                char c[elements_strFormat_len+1];
                strcpy(c, elements_strFormat.c_str());
                SHA256::computeDigest(c, elements_strFormat_len, temp_hash);
                hashes.push_back(temp_hash);
            }
                
            
            // Minichain's accumulator update
            std::cout << "yo\n";
            MerkleTree tree, txo_tree;
            vector<unsigned char> mc_TXO_C, TMR;
            MerkleAccumulator::accumulate(hashes, tree);
            tree.getRoot(TMR);    
            txo_tree.getRoot(mc_TXO_C);
            double Start = Profiler::getCurrentTime();
          //       RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator), rep_a, threadPool);
                // RSAAccumulator::batchAdd(rep_a, rsaKey, prev_acc_minichain, A, Q_A);
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                    RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator), rep_a, threadPool);
                    RSAAccumulator::batchAdd(rep_a, rsaKey, prev_acc_minichain, A, Q_A);
                }));
                itr++;
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                    mmr.updateTree(TMR, prev_peaks);
                    MerkleAccumulator::accumulate(prev_peaks, txo_tree);
                    mmr.prove(L, proof);
                    MerkleAccumulator::proveHash(prev_peaks.size()-1, txo_tree, MMR_MerkelProof);
                }));
                for(auto& future : futures) {
                    future.get();
                }
            double End = Profiler::getCurrentTime();
            time_minichain.push_back(End - Start);
            cout << "Minichain's time " << (End - Start) << endl;
            
            itr=0;
            futures.clear();

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
            
            bool b, isVerify_mmr, isVerify_mmr_mt;;
            itr=0;
            futures.clear();
            double StartVerify = Profiler::getCurrentTime();
                // RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator), rep_a_V, threadPool);
                // RSAAccumulator::NIPoE_Verify(rsaKey, rep_a_V, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc_minichain, A, Q_A, b);
                futures.push_back(threadPool.enqueue<void>([&, itr](){
                    mmr.verify(L, proof, isVerify_mmr);
                    MerkleAccumulator::verifyHash(MMR_MerkelProof, txo_tree, isVerify_mmr_mt);
                }));
                futures.push_back(threadPool.enqueue<void>([&, itr]() {
                    RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator), rep_a_V, threadPool);
                    RSAAccumulator::NIPoE_Verify(rsaKey, rep_a_V, *(rsaKey.getPublicKey().primeRepGenerator), prev_acc_minichain, A, Q_A, b);
                }));
                for(auto& future : futures) {
                    future.get();
                }
            double EndVerify = Profiler::getCurrentTime();

            time_verify_minichain.push_back(EndVerify - StartVerify);
            if(b)
                cout << "NI-PoE proof for the minichain's STXO_C  is verified successfully" << endl;
            else
                cout << "NI-PoE proof verification for the minichain's STXO_C failed" << endl;

            if(isVerify_mmr&&isVerify_mmr_mt)
                cout << "MMR Inclusion proof for the minichain's TXO_C  is verified successfully" << endl;
            else
                cout << "MMR Inclusion proof verification for the minichain's TXO_C failed" << endl;
            itr = 0;
            futures.clear();
            bool b_TXO, b_STXO;
            
            StartVerify = Profiler::getCurrentTime();
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
            EndVerify = Profiler::getCurrentTime();
            itr=0;
            futures.clear();
            time_verify_proposed.push_back(EndVerify - StartVerify);
            if(b_TXO == 1)
                cout << "\nNI-PoE proof for the proposed protocol's TXO_C  is verified successfully" << endl;
            else
                cout << "\nNI-PoE proof verification for the proposed protocol's TXO_C failed" << endl;
            
            if(b_STXO == 1)
                cout << "NI-PoE proof for the proposed protocol's STXO_C  is verified successfully" << endl;
            else
                cout << "NI-PoE proof verification for the proposed protocol's STXO_C failed" << endl;
            
            }
            for(int g=0;g<len;g++){
                Time_minichain[g] += time_minichain[g];
                Time_proposed[g] += time_proposed[g];
                Time_verify_minichain[g] += time_verify_minichain[g];
                Time_verify_proposed[g] += time_verify_proposed[g];
            }
        }
    for(int g=0;g<len;g++){
        Time_minichain[g] /= MC;
        Time_proposed[g] /= MC;
        Time_verify_minichain[g] /= MC;
        Time_verify_proposed[g] /= MC;
    }
    std::ofstream file, file1;
    file.open("./results/minichain/Data/testAccUp_result_new"+ index +".csv");
    file << "N,Time taken\n";
    file1.open("./results/proposed/Data/testAccUp_result_new"+ index +".csv");
    file1 << "N,Time taken\n";
	cout << "\n/*-----------------Accumulator Update time-----------------------------*/" << endl;
	for(size_t i = 0; i < len; i++) {
		cout << "\n/*-----------Numeber of elements: " << (i+1)*step << " -----------------*/" << endl;
		cout << "Minichain accumulator update time: " << Time_minichain.at(i) << " seconds"  << endl;
		cout << "Proposed accumulator update time : " << Time_proposed.at(i) << " seconds" << endl;
        //file << to_string((i+1)*step)+","+to_string(time_minichain.at(i))+","+to_string(time_proposed.at(i))+"\n";
        file << to_string((i+1)*step)+","+to_string(Time_minichain.at(i))+"\n";
        file1 << to_string((i+1)*step)+","+to_string(Time_proposed.at(i))+"\n";
	}
	file.close();
    file1.close();
    
    file.open("./results/minichain/Data/testAccVer_result"+ index +".csv");
    file << "N,Time taken\n";
    file1.open("./results/proposed/Data/testAccVer_result"+ index +".csv");
    file1 << "N,Time taken\n";
	cout << "\n/*-----------------Accumulator verification time------------------------------------*/" << endl;
	for(size_t i = 0; i < len; i++) {
		cout << "\n/*-----------Numeber of elements: " << (i+1)*step << " -----------------*/" << endl;
		cout << "NI-PoE verification time for the minichain " << Time_verify_minichain.at(i) << " seconds" << endl;
		cout << "NI-PoE verification time for the proposed  " << Time_verify_proposed.at(i) << " seconds" << endl;
        //file << to_string((i+1)*step)+","+to_string(time_verify_minichain.at(i))+","+to_string(time_verify_proposed.at(i))+"\n";
        file << to_string((i+1)*step)+","+to_string(Time_verify_minichain.at(i))+"\n";
        file1 << to_string((i+1)*step)+","+to_string(Time_verify_proposed.at(i))+"\n";
	}
 }

}  // namespace testAccUp
