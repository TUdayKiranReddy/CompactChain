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

typedef vector<pair<vector<unsigned char>, bool>> MMRProof;


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

    /*-------------------Creating MMRTree---------------------------*/
    vector<string> Hhashes = readSHA256("randomSHA2561000000");
    vector<vector<unsigned char>> TMRhashes;
    string2vv_unsign_char(Hhashes, TMRhashes);

    int L = int(1e6);
    cout << "L:- " << L << endl;
    vector<vector<unsigned char>> E_1;
    for(int i=0;i<L;i++)
        E_1.push_back(TMRhashes[i]);
    
    // Freeing Memory
    Hhashes.erase(Hhashes.begin(), Hhashes.end());
    Hhashes.shrink_to_fit();

    TMRhashes.erase(TMRhashes.begin(), TMRhashes.end());
    TMRhashes.shrink_to_fit();

    MMRTree mmr;
    vector<vector<unsigned char>> prev_peaks;
    mmr.constructTree(E_1, prev_peaks);

   ///*--------------Verify transaction validity in minichain---------------------*/
    //Non-Membership verification in STXO_C
    flint::BigMod prev_acc;
    prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
    prev_acc = rsaKey.getPublicKey().base;
    flint::BigMod prev_acc_stxo(prev_acc), prev_acc_txo(prev_acc);
    vector<double> time_minichain, time_minichain_mem, time_minichain_nonmem;
    vector<double> time_minichain_batch, time_minichain_batch_nonmem, time_minichain_batch_mem;
    int len = 125;
    int Ntx = 8; //Total transaction for verification

    cout<<"\n/*--------------------------------------------------------*/\n";
    vector<flint::BigInt> elements_TXO, elements_STXO;
    vector<vector<unsigned char>> hashes;
    vector<unsigned char> TMR;
    flint::BigMod  A, Q_A, d, w;
    flint::BigInt b;
    vector<future<void>> futures;
    int itr=0;

    vector<unsigned char> temp_hash; 
    string elements_strFormat;
    int elements_strFormat_len;

    size_t j;
    for(j = 0; j < 1000; j++){
        elements_STXO.push_back(elements[j]);
        //cout << j << endl;
        
        elements_TXO.push_back(elements[j+1000]);
        //cout << j+1000 << endl;
        
        // Hashing TXO elements
        elements_strFormat = elements[j+1000].toHex();
        elements_strFormat_len = elements_strFormat.length();
        char c[elements_strFormat_len+1];
        strcpy(c, elements_strFormat.c_str());
        SHA256::computeDigest(c, elements_strFormat_len, temp_hash);
        hashes.push_back(temp_hash);
    }

    std::vector<flint::BigInt> rep_A(elements_STXO.size()), rep_STXO(elements_STXO.size()), rep_TXO(elements_TXO.size());
    MerkleTree tree, txo_tree;
    vector<unsigned char> mc_TXO_C;
    futures.push_back(threadPool.enqueue<void>([&, itr](){
        // Creating a Merkle Tree
        MerkleAccumulator::accumulate(hashes, tree);
        tree.getRoot(TMR);
        mmr.updateTree(TMR, prev_peaks);
        MerkleAccumulator::accumulate(prev_peaks, txo_tree);
        txo_tree.getRoot(mc_TXO_C);
    }));
    itr++;
    futures.push_back(threadPool.enqueue<void>([&, itr](){
        // Minichain's tx validity performance
        RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_A, threadPool);
        RSAAccumulator::batchAdd(rep_A, rsaKey, prev_acc, A, Q_A);
    }));
    for(auto& future:futures)
        future.get();
    itr=0;
    futures.clear();
    

    /*----------------------Single Transaction Proof---------------------------*/
    flint::BigInt x_m = elements[j];
    vector<HashNode> Merkleproof, MMR_MerkelProof;
    MMRProof mmrproof;
    futures.push_back(threadPool.enqueue<void>([&, itr](){
        // Non Mem proof in STXO
        RSAAccumulator::CreateNonMemWit(x_m, rep_A, rsaKey, prev_acc, d, b);
    }));
    itr++;
    futures.push_back(threadPool.enqueue<void>([&, itr](){
        // Mem Proof in TXO
        MerkleAccumulator::proveHash(j, tree, Merkleproof);
        mmr.prove(L, mmrproof);
        MerkleAccumulator::proveHash(prev_peaks.size()-1, txo_tree, MMR_MerkelProof);
    }));
    for(auto& future:futures)
        future.get();
    itr=0;
    futures.clear();

    /*----------------------1000 Transactions Proofs---------------------------*/
    
    vector<flint::BigInt> X_m(Ntx);
    for(int p=0;p<Ntx;p++)
        X_m[p] = elements[j];

    vector<flint::BigMod> D(Ntx);
    vector<flint::BigInt> B(Ntx);

    vector<vector<HashNode>> Merkleproofs(Ntx), MMR_MerkelProofs(Ntx);
    vector<MMRProof> mmrproofs(Ntx);


    for(int p=0;p<Ntx;p++){
        // Non Mem proof in STXO
        futures.push_back(threadPool.enqueue<void>([&, p]{
            RSAAccumulator::CreateNonMemWit(X_m.at(p), rep_A, rsaKey, prev_acc, D.at(p), B.at(p));
        }));
    }
    for(int p=0;p<Ntx;p++){
        // Mem Proof in TXO
        futures.push_back(threadPool.enqueue<void>([&, p]{
            MerkleAccumulator::proveHash(j, tree, Merkleproofs.at(p));
            mmr.prove(L, mmrproofs[p]);
            MerkleAccumulator::proveHash(prev_peaks.size()-1, txo_tree, MMR_MerkelProofs.at(p));
        }));
    }
    for(auto& future:futures)
            future.get();
    
    itr=0;
    futures.clear();
    int avr_itr = 10;

    for(int i=0;i<avr_itr*len;i++){
        itr = 0;
        futures.clear();

        cout << "/*----------------------Single Transaction Verfication---------------------------*/" << endl;
        //Parralel Execution
        bool ans, isVerify_mt, isVerify_mmrt, isVerify_mmr_mt;
        double Start = Profiler::getCurrentTime();
            futures.push_back(threadPool.enqueue<void>([&, itr](){
                RSAAccumulator::VerifyNonMemWit(x_m, rsaKey, A, prev_acc, d, b, ans);
            }));
            itr++;
            futures.push_back(threadPool.enqueue<void>([&, itr](){
                MerkleAccumulator::verifyHash(Merkleproof, tree, isVerify_mt);
                mmr.verify(L, mmrproof, isVerify_mmrt);
                MerkleAccumulator::verifyHash(MMR_MerkelProof, txo_tree, isVerify_mmr_mt);
            }));
            for(auto& future:futures)
                future.get();
        double End = Profiler::getCurrentTime();
        time_minichain.push_back(End-Start);

        //Sequential Execution
        Start = Profiler::getCurrentTime();
                RSAAccumulator::VerifyNonMemWit(x_m, rsaKey, A, prev_acc, d, b, ans);
        double nonmemEnd = Profiler::getCurrentTime();
                MerkleAccumulator::verifyHash(Merkleproof, tree, isVerify_mt);
                mmr.verify(L, mmrproof, isVerify_mmrt);
                MerkleAccumulator::verifyHash(MMR_MerkelProof, txo_tree, isVerify_mmr_mt);
        End = Profiler::getCurrentTime();
        
        time_minichain_nonmem.push_back(nonmemEnd - Start);
        time_minichain_mem.push_back(End - nonmemEnd);
        
        itr=0;
        futures.clear();
        
        cout << "\nTime consumed to verify a transaction in Minichain: " << time_minichain[i] << endl;
        if(ans)
            cout << "Non-Membership Witness in STXO verified!" << endl;
        else
            cout << "Non-Membership Witness in STXO not verified!!" << endl;
        cout << "Time consumed to verify Non-Membership Witness in Minichain: " << time_minichain_nonmem[i] << endl;

        if(isVerify_mt&&isVerify_mmrt&&isVerify_mmr_mt)
            cout << "\nMembership Witness in TXO verified!" << endl;
        else
            cout << "\nMembership Witness in TXO not verified!!" << endl;
        cout << "Time consumed to verify Membership Witness in Minichain: " << time_minichain_mem[i] << endl;

        

        cout << "/*----------------------1000 Transactions Verfications---------------------------*/\n";
        //Parralel Execution
        bool anss, isVerify_mts, isVerify_mmrts, isVerify_mmr_mts;

        Start = Profiler::getCurrentTime();
            for(int p=0;p<Ntx;p++){
                futures.push_back(threadPool.enqueue<void>([&, p](){
                    RSAAccumulator::VerifyNonMemWit(X_m.at(p), rsaKey, A, prev_acc, D.at(p), B.at(p), anss);
                }));
            }
            for(int p=0;p<Ntx;p++){
                futures.push_back(threadPool.enqueue<void>([&, p](){
                    MerkleAccumulator::verifyHash(Merkleproofs.at(p), tree, isVerify_mts);
                    mmr.verify(L, mmrproofs.at(p), isVerify_mmrts);
                    MerkleAccumulator::verifyHash(MMR_MerkelProofs.at(p), txo_tree, isVerify_mmr_mts);
                }));
            }
            for(auto& future:futures)
                future.get();
        End = Profiler::getCurrentTime();
        time_minichain_batch.push_back(End-Start);

        //Sequential Execution
        Start = Profiler::getCurrentTime();
            for(int p=0;p<Ntx;p++){
                RSAAccumulator::VerifyNonMemWit(X_m.at(p), rsaKey, A, prev_acc, D.at(p), B.at(p), anss);
            }
        nonmemEnd = Profiler::getCurrentTime();
            for(int p=0;p<Ntx;p++){
                MerkleAccumulator::verifyHash(Merkleproofs.at(p), tree, isVerify_mts);
                mmr.verify(L, mmrproofs.at(p), isVerify_mmrts);
                MerkleAccumulator::verifyHash(MMR_MerkelProofs.at(p), txo_tree, isVerify_mmr_mts);
            }
        End = Profiler::getCurrentTime();
        
        time_minichain_batch_nonmem.push_back(nonmemEnd - Start);
        time_minichain_batch_mem.push_back(End - nonmemEnd);
        
        itr=0;
        futures.clear();
        
        cout << "\nTime consumed to verify a transaction in Minichain: " << time_minichain_batch[i] << endl;
        bool x=anss, y=isVerify_mts&&isVerify_mmrts&&isVerify_mmr_mts;
        // for(int p=1;p<Ntx;p++){
        //     x &= anss[p];
        //     y &= isVerify_mts[p]&&isVerify_mmrts[p]&&isVerify_mmr_mts[p];
        // }
        if(x)
            cout << "Non-Membership Witness in STXO verified!" << endl;
        else
            cout << "Non-Membership Witness in STXO not verified!!" << endl;
        cout << "Time consumed to verify Non-Membership Witness in Minichain: " << time_minichain_batch_nonmem[i] << endl;

        if(y)
            cout << "\nMembership Witness in TXO verified!" << endl;
        else
            cout << "\nMembership Witness in TXO not verified!!" << endl;
        cout << "Time consumed to verify Membership Witness in Minichain: " << time_minichain_batch_mem[i] << endl;   
    }

	double mini_avg = 0.0, mini_avg_mem = 0.0, mini_avg_nonmem = 0.0;
    double mini_avg_batch = 0.0, mini_avg_batch_mem = 0.0, mini_avg_batch_nonmem = 0.0;

	for(size_t i = 0; i < avr_itr*len; ++i){
		mini_avg += time_minichain[i];
		mini_avg_nonmem += time_minichain_nonmem[i];
		mini_avg_mem += time_minichain_mem[i];
        mini_avg_batch += time_minichain_batch[i];
        mini_avg_batch_nonmem += time_minichain_batch_nonmem[i];
        mini_avg_batch_mem += time_minichain_batch_mem[i];
	}

	mini_avg /= (avr_itr*len);
	mini_avg_nonmem /= (avr_itr*len);
	mini_avg_mem /= (avr_itr*len);

    // mini_avg_batch /= len;
    // mini_avg_batch_nonmem /= len;
    // mini_avg_batch_mem /= len;
    mini_avg_batch /= avr_itr;
    mini_avg_batch_nonmem /= avr_itr;
    mini_avg_batch_mem /= avr_itr;

    std::ofstream file;
    file.open("./results/minichain/FinalTXOVerification.csv");
    file << "Parallel, Non-Mem, Mem\n";
    cout << "\n/*-------------------------Average Single Transaction Verification time over "<< len << " Iterations------------------------------*/\n";
	cout << "\nAverage Time consumed to verify a transaction(parallel) in Minichain: " << mini_avg << endl;
	cout << "Average Time consumed to verify a Non-Mem Wit in Minichain: " << mini_avg_nonmem << endl;
	cout << "Average Time consumed to verify a Mem Wit in Minichain: " << mini_avg_mem << endl;
    file << mini_avg << "," << mini_avg_nonmem << "," << mini_avg_mem << "\n\n";

    cout << "\n/*-------------------------Average " << Ntx <<  " Transactions Verification time over "<< len << " Iterations----------------*/\n";
    cout << "\nAverage Time consumed to verify a transactions(parallel) in Minichain: " << mini_avg_batch << endl;
    cout << "Average Time consumed to verify a Non-Mem Wit in Minichain: " << mini_avg_batch_nonmem << endl;
    cout << "Average Time consumed to verify a Mem Wit in Minichain: " << mini_avg_batch_mem << endl;
    file << mini_avg_batch << "," << mini_avg_batch_nonmem << "," << mini_avg_batch_mem << "\n";
    file.close();
}