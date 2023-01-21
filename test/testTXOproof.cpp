
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

namespace speedtest {
void txTest(int setSize);
vector<flint::BigInt> readBigInts(string filename);
vector<string> readSHA256(string filename);
void string2vv_unsign_char(const vector<string> elements, vector<vector<unsigned char>>& hashes);
}  // namespace speedtest

int main(int argc, char** argv) {
    int setSize;
    if(argc > 1) {
        setSize = atoi(argv[1]);
    } else {
        setSize = 20000;
    }
    speedtest::txTest(setSize);
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

void txTest(int setSize) {
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
  
    int size = 200;
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
    RSAAccumulator::witnessesForSet(representatives, rsaKey.getPublicKey(), witnesses, threadPool);
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
	prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
	prev_acc = rsaKey.getPublicKey().base;
	flint::BigMod prev_acc_stxo(prev_acc), prev_acc_txo(prev_acc);
	vector<double> time_minichain, time_proposed, time_verify_minichain, time_verify_proposed;
	//vector<double> time_minichain_mem, time_minichain_nonmem, time_proposed_mem, time_proposed_nonmem;
	//vector<flint::BigMod> W(10);
	int len = 20;
    size_t elements_PREV_OUTPUTS = 200;
    size_t elements_CURR_OUTPUTS = 200;
    double time_tx_verify=0.0;

	for(size_t i = 0; i < len; ++i) {
		cout<<"\n/*--------------------------------------------------------*/\n";
		vector<flint::BigInt> elements_TXO, elements_STXO;
		vector<vector<unsigned char>> hashes;
		vector<unsigned char> TMR;
		flint::BigMod TXO_C, STXO_C, A, Q_TXO, Q_STXO, Q_A, d, w;
		flint::BigInt b;
        vector<future<void>> futures;
        int itr=0;

        vector<unsigned char> temp_hash; 
        string elements_strFormat;
        int elements_strFormat_len;

		size_t j;
		for(j = i*1000; j < (i+1)*1000; j++){
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
			
		
		//cout << "Minichain's time" << (End - Start) << endl;
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
			MerkleAccumulator::proveHash(j-i*1000, tree, Merkleproof);
			mmr.prove(L, mmrproof);
			MerkleAccumulator::proveHash(prev_peaks.size()-1, txo_tree, MMR_MerkelProof);
		}));
		for(auto& future:futures)
			future.get();
		itr=0;
		futures.clear();
	
		bool ans, isVerify_mt, isVerify_mmrt, isVerify_mmr_mt;
		double Start = Profiler::getCurrentTime();
			futures.push_back(threadPool.enqueue<void>([&, itr](){
		    	RSAAccumulator::VerifyNonMemWit(x_m, rsaKey, A, prev_acc, d, b, ans);
		    }));
		    itr++;
		// double nonmemEnd = Profiler::getCurrentTime();
		    futures.push_back(threadPool.enqueue<void>([&, itr](){
			    MerkleAccumulator::verifyHash(Merkleproof, tree, isVerify_mt);
			    mmr.verify(L, mmrproof, isVerify_mmrt);
			    MerkleAccumulator::verifyHash(MMR_MerkelProof, txo_tree, isVerify_mmr_mt);
			}));
			for(auto& future:futures)
				future.get();
		double End = Profiler::getCurrentTime();
		time_minichain.push_back(End-Start);
		// time_minichain_nonmem.push_back(nonmemEnd - Start);
		// time_minichain_mem.push_back(End - nonmemEnd);
		itr=0;
		futures.clear();
		cout << "Time consumed to verify a transaction in Minichain: " << time_minichain[i] << endl;
		if(ans)
			cout << "\nNon-Membership Witness in STXO verified!" << endl;
		else
			cout << "\nNon-Membership Witness in STXO not verified!!" << endl;
		//cout << "Time consumed to verify Non-Membership Witness in Minichain: " << time_minichain_nonmem[i] << endl;

		if(isVerify_mt&&isVerify_mmrt&&isVerify_mmr_mt)
			cout << "\nMembership Witness in TXO verified!" << endl;
		else
			cout << "\nMembership Witness in TXO not verified!!" << endl;
		//cout << "Time consumed to verify Membership Witness in Minichain: " << time_minichain_mem[i] << endl;
	
		// CompactChain's tx validity performance
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
		itr=0;
		futures.clear();
		bool b1, b2;
		Start = Profiler::getCurrentTime();
             futures.push_back(threadPool.enqueue<void>([&, itr](){
                 RSAAccumulator::VerifyNonMemWit(x_stxo, rsaKey, STXO_C, prev_acc_stxo, d, b, b1);    
             }));
    		itr++;
        //nonmemEnd = Profiler::getCurrentTime();
            futures.push_back(threadPool.enqueue<void>([&, itr](){
    		  RSAAccumulator::verify(x_txo, W[0], TXO_C, rsaKey.getPublicKey(), b2);
            }));
            for(auto& future:futures)
                future.get();
        End = Profiler::getCurrentTime();
		time_proposed.push_back(End - Start);
		// time_proposed_nonmem.push_back(nonmemEnd - Start);
		// time_proposed_mem.push_back(End - nonmemEnd);
		itr=0;
		futures.clear();
		cout << "\nTime consumed to verify a transaction in CompactChain: " << time_proposed[i] << endl;
		if(b1)
			cout << "Non-Membership Witness in STXO verified!" << endl;
		else
			cout << "Non-Membership Witness in STXO not verified!!" << endl;
		//cout << "Time consumed to verify Non-Membership Witness in CompactChain: " << time_proposed_nonmem[i] << endl;

		if(b2)
			cout << "Membership Witness in TXO verified!" << endl;
		else
			cout << "Membership Witness in TXO not verified!!" << endl;
		//cout << "Time consumed to verify Membership Witness in CompactChain: " << time_proposed_mem[i] << endl;
		
		vector<flint::BigInt> x_list(elements_PREV_OUTPUTS);
	    vector<flint::BigInt> y_list(elements_CURR_OUTPUTS);
	    vector<flint::BigInt> reps_y(elements_CURR_OUTPUTS), reps_y_v(elements_CURR_OUTPUTS);
	    vector<flint::BigMod> proofs_list(elements_PREV_OUTPUTS);
	    flint::BigMod A_post_delete, A_, A_final, proof_D;
        flint::BigInt p;

	    futures.clear();
	    itr = 0;

	    flint::BigMod Q_a;
	    for(size_t i=0;i<elements_PREV_OUTPUTS;i++){
	        x_list[i] = e_1[size  -1 - i];
	        proofs_list[i] = witnesses[size  - 1 - i];
	    }
	    for(size_t i=0;i<elements_CURR_OUTPUTS;i++)
	        y_list[i] = elements[size+i];

        RSAAccumulator::batch_delete_using_membership_proofs(acc, x_list, proofs_list, rsaKey.getPublicKey(), *(rsaKey.getPublicKey().primeRepGenerator),
                                                             A_post_delete, p, proof_D, threadPool);
        A_ = A_post_delete;
        RSAAccumulator::genRepresentatives(y_list, *(rsaKey.getPublicKey().primeRepGenerator), reps_y, threadPool);
        RSAAccumulator::batchAdd(reps_y, rsaKey, A_, A_final, Q_a);


	    vector<flint::BigInt> rep_post_update;
	    for(int l=0;l<(size+elements_CURR_OUTPUTS);l++){
	        if(l<(size-elements_PREV_OUTPUTS))
	            rep_post_update.push_back(representatives[l]);
	        else if(l>(size-1))
	            rep_post_update.push_back(reps_y[l-size]);
	    }

	    /*---------Witness generation-----------------*/
	    vector<flint::BigMod> Wit(size + elements_CURR_OUTPUTS - elements_PREV_OUTPUTS);
	    RSAAccumulator::witnessesForSet(rep_post_update, rsaKey, Wit, threadPool);

	    j=0;
	    flint::BigInt tx = y_list[j];

	    /*---------Witness verification---------------*/
	    double verStart = Profiler::getCurrentTime();
	    RSAAccumulator::verify(tx, Wit[j+size-elements_PREV_OUTPUTS], A_final, rsaKey.getPublicKey(), ans);
	    double verEnd = Profiler::getCurrentTime();
	    time_tx_verify += (verEnd-verStart);
	    cout << "\nTime taken to verify transaction in boneh is " << (verEnd-verStart) << " seconds\n";
		
	} 
	double mini_avg = 0.0, compact_avg = 0.0;
	for(size_t i = 0; i < len; ++i){
		mini_avg += time_minichain[i];
		compact_avg += time_proposed[i];
	}
	mini_avg /= len;
	compact_avg /= len;
	time_tx_verify /= len;

	cout << "Average Time consumed to verify a transaction in Minichain: " << mini_avg << endl;
	cout << "Average Time consumed to verify a transaction in CompactChain: " << compact_avg << endl;
	cout << "\nAverage time taken to verify transaction in boneh is " << time_tx_verify << " seconds\n";
	
	// double mini_avg_nonmem = 0.0, mini_avg_mem = 0.0, compact_avg_nonmem = 0.0, compact_avg_mem = 0.0;
	// for(size_t i = 0; i < 20; ++i){
	// 	mini_avg_nonmem += time_minichain_nonmem[i];
	// 	mini_avg_mem += time_minichain_mem[i];
	// 	compact_avg_nonmem += time_proposed_nonmem[i];
	// 	compact_avg_mem += time_proposed_mem[i];
	// }
	// mini_avg_nonmem /= 20;
	// mini_avg_mem /= 20;
	// compact_avg_nonmem /= 20;
	// compact_avg_mem /= 20;
	// cout << "Average Time consumed to verify a Non-Membership witnesses in Minichain: " << mini_avg_nonmem << endl;
	// cout << "Average Time consumed to verify a Membership witnesses in Minichain: " << mini_avg_mem << endl;
	// cout << "Average Time consumed to verify a Non-Membership witness in CompactChain: " << compact_avg_nonmem << endl;
	// cout << "Average Time consumed to verify a Membership witnesses in CompactChain: " << compact_avg_mem << endl;
}
}  // namespace speedtest

