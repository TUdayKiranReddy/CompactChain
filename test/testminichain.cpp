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
#include <algorithms/MMRTree.hpp>

#include <utils/Pointers.hpp>
#include <utils/Profiler.hpp>
#include <utils/ThreadPool.hpp>
#include <utils/LibConversions.hpp>
#include <utils/SHA256.hpp>

#include <flint/BigInt.hpp>
#include <flint/BigMod.hpp>
#include <flint/Random.hpp>

using namespace std;

namespace testminichain_Accup {
    void test(size_t setSize, string index);
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
    testminichain_Accup::test(setSize, index.str());

    return 0;
}

namespace testminichain_Accup {
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

    void test(size_t setSize, string index) {
        // cout << "RSA Accumulator test:" << endl;
        static const int THREAD_POOL_SIZE = 16;
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
    	prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
        prev_acc = rsaKey.getPublicKey().base;
        vector<double> time_minichain, time_verify_minichain;

        vector<string> Hhashes = readSHA256("randomSHA25610000");
        vector<vector<unsigned char>> hashes;
        string2vv_unsign_char(Hhashes, hashes);

        vector<vector<unsigned char>> E_1;
        for(int i=0;i<L;i++)
            E_1.push_back(hashes[i]);

        MMRTree mmr;
        vector<vector<unsigned char>> prev_peaks;
        mmr.constructTree(E_1, prev_peaks);
        mmr.printTree();

        flint::BigMod prev_acc_minichain(prev_acc);

        size_t len = 5;
        int step = 200;
        for(size_t i = 0; i < len; i++) {
            // Setting size of sets
            size_t STXO_SIZE = (i+1)*step;
            size_t TXO_SIZE  = (i+1)*step;

            vector<flint::BigInt> elements_STXO, elements_TXO;
            flint::BigMod A, Q_A;
            vector<flint::BigInt> rep_a(STXO_SIZE);
            vector<flint::BigInt> rep_a_V(STXO_SIZE);
            vector<future<void>> futures;
            Proof proof;
            vector<HashNode> MMR_MerkelProof;
            vector<unsigned char> temp_hash; 
            vector<vector<unsigned char>> hashes;
            string elements_strFormat;
            int elements_strFormat_len;

            int itr = 0;

            // Setting Random elements to each Set
            for(size_t j = size; j < size + STXO_SIZE; j++)
                elements_STXO.push_back(elements[j]);
                
            for(size_t j = size + STXO_SIZE;j<size + STXO_SIZE + TXO_SIZE;j++){
                elements_TXO.push_back(elements[j]);

                //Hashing TXO
                elements_strFormat = elements[j].toHex();
                elements_strFormat_len = elements_strFormat.length();
                char c[elements_strFormat_len+1];
                strcpy(c, elements_strFormat.c_str());
                SHA256::computeDigest(c, elements_strFormat_len, temp_hash);
                hashes.push_back(temp_hash);
            }
            MerkleTree tree, txo_tree;
            vector<unsigned char> TXO_C, TMR;


            MerkleAccumulator::accumulate(hashes, tree);
            tree.getRoot(TMR);
            
            txo_tree.getRoot(TXO_C);
            // Minichain's accumulator update
            double Start = Profiler::getCurrentTime();
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

            // Minichain's accumulator update Verfication
            bool b, isVerify_mmr, isVerify_mmr_mt;
            
            double StartVerify = Profiler::getCurrentTime();
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
            
        }
        std::ofstream file;
        file.open("./results/minichain/Data/testAccUp_result"+ index +".csv");
        file << "N,Time taken\n";
        cout << "\n/*-----------------Accumulator Update time-----------------------------*/" << endl;
        for(size_t i = 0; i < len; i++) {
            cout << "\n/*-----------Numeber of elements: " << (i+1)*step << " -----------------*/" << endl;
            cout << "Minichain accumulator update time: " << time_minichain.at(i) << " seconds"  << endl;
            file << to_string((i+1)*step)+","+to_string(time_minichain.at(i))+"\n";
        }
        file.close();
        
        file.open("./results/minichain/Data/testAccVer_result"+ index +".csv");
        file << "N,Time taken\n";
        cout << "\n/*-----------------Accumulator verification time------------------------------------*/" << endl;
        for(size_t i = 0; i < len; i++) {
            cout << "\n/*-----------Numeber of elements: " << (i+1)*step << " -----------------*/" << endl;
            cout << "NI-PoE verification time for the minichain " << time_verify_minichain.at(i) << " seconds" << endl;
            file << to_string((i+1)*step)+","+to_string(time_verify_minichain.at(i))+"\n";
        }
    } 

}  // namespace testminichain_Accup