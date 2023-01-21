#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
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

namespace testWitUp {
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
    setSize = 1000000;
    testWitUp::test(setSize, index.str());

    return 0;
}

namespace testWitUp {

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

    void test(size_t setSize, string index) {
        // cout << "RSA Accumulator test:" << endl;
        static const int THREAD_POOL_SIZE = 16;
        static const int RSA_KEY_SIZE = 3072; //bits
        size_t size = 2000;

        // ThreadPool threadPool(THREAD_POOL_SIZE);
        ThreadPool threadPool_1(THREAD_POOL_SIZE/2);
        ThreadPool threadPool_2(THREAD_POOL_SIZE/2);

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
                                           representatives, threadPool_1);
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

        cout << "\n/*---------Gennerate witnesses for all elements-----------------*/" << endl;
		//Generate witnesses for all of the representatives
		vector<flint::BigMod> witnesses(size);
		double witStart = Profiler::getCurrentTime();
		RSAAccumulator::witnessesForSet(representatives, rsaKey, witnesses, threadPool_1);
		double witEnd = Profiler::getCurrentTime();
		cout << "Generated " << witnesses.size() << " witnesses in " << (witEnd-witStart) << " seconds with private key" << endl;
		// cout << (witEnd - witStart) << endl;

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

        vector<flint::BigInt> Elements_TXO, Elements_STXO;
        vector<vector<unsigned char>> hashes;
        vector<unsigned char> TMR;
        flint::BigMod  a, q_a, d, w;
        flint::BigInt b;
        vector<future<void>> futures;
        int itr=0;

        vector<unsigned char> temp_hash; 
        string elements_strFormat;
        int elements_strFormat_len;

        size_t j;
        for(j = 0; j < (size/2); j++){
            Elements_STXO.push_back(elements[j]);
            //cout << j << endl;
            
            Elements_TXO.push_back(elements[j+(size/2)]);
            //cout << j+1000 << endl;
            
            // Hashing TXO elements
            elements_strFormat = elements[j+(size/2)].toHex();
            elements_strFormat_len = elements_strFormat.length();
            char c[elements_strFormat_len+1];
            strcpy(c, elements_strFormat.c_str());
            SHA256::computeDigest(c, elements_strFormat_len, temp_hash);
            hashes.push_back(temp_hash);
        }
        std::vector<flint::BigInt> rep_a(Elements_STXO.size()), rep_stxo(Elements_STXO.size()), rep_txo(Elements_TXO.size());

        /*MiniChain*/
        MerkleTree Tree, txo_tree;
        vector<unsigned char> mc_TXO_C;
        futures.push_back(threadPool_1.enqueue<void>([&, itr](){
            // Creating a Merkle Tree
            MerkleAccumulator::accumulate(hashes, Tree);
            Tree.getRoot(TMR);
            mmr.updateTree(TMR, prev_peaks);
            MerkleAccumulator::accumulate(prev_peaks, txo_tree);
            txo_tree.getRoot(mc_TXO_C);
        }));
        itr++;
        futures.push_back(threadPool_2.enqueue<void>([&, itr](){
            // Minichain's tx validity performance
            RSAAccumulator::genRepresentatives(Elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_a, threadPool_2);
            RSAAccumulator::batchAdd(rep_a, rsaKey, prev_acc, a, q_a);
        }));
        for(auto& future:futures)
            future.get();
        itr=0;
        futures.clear();
        

        /*----------------------Single Transaction Proof---------------------------*/
        flint::BigInt x_m = elements[0];
        vector<HashNode> Merkleproof, MMR_MerkelProof;
        MMRProof mmrproof;
        futures.push_back(threadPool_1.enqueue<void>([&, itr](){
            // Non Mem proof in STXO
            RSAAccumulator::CreateNonMemWit(x_m, rep_a, rsaKey, prev_acc, d, b);
        }));
        itr++;
        futures.push_back(threadPool_2.enqueue<void>([&, itr](){
            // Mem Proof in TXO
            MerkleAccumulator::proveHash(j, Tree, Merkleproof);
            mmr.prove(L, mmrproof);
            MerkleAccumulator::proveHash(prev_peaks.size()-1, txo_tree, MMR_MerkelProof);
        }));
        for(auto& future:futures)
            future.get();
        itr=0;
        futures.clear();

        /*CompactChain*/
        flint::BigMod prev_acc_stxo(prev_acc), prev_acc_txo(prev_acc);
        flint::BigMod TXO_C, STXO_C, q_txo, q_stxo;
        futures.push_back(threadPool_1.enqueue<void>([&, itr]() {
                RSAAccumulator::genRepresentatives(Elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator), rep_stxo, threadPool_1);
            }));
        itr++;
        futures.push_back(threadPool_2.enqueue<void>([&, itr]() {
                RSAAccumulator::genRepresentatives(Elements_TXO, *(rsaKey.getPublicKey().primeRepGenerator), rep_txo, threadPool_2);
            }));
        
        for(auto& future : futures) {
            future.get();
        }
        itr = 0;
        futures.clear();
        futures.push_back(threadPool_1.enqueue<void>([&, itr]() {
                RSAAccumulator::batchAdd(rep_txo, rsaKey, prev_acc_stxo, TXO_C, q_txo);
            }));
        itr++;
        futures.push_back(threadPool_2.enqueue<void>([&, itr]() {
                RSAAccumulator::batchAdd(rep_stxo, rsaKey, prev_acc_txo, STXO_C, q_stxo);
            }));
        
        for(auto& future : futures) {
            future.get();
        }
        itr=0;
        futures.clear();    
        /*-----------------------Single Transaction proof-------------------------------------*/
        vector<flint::BigMod> Wcc(Elements_TXO.size());
        flint::BigMod dcc;
        flint::BigInt bcc;

        flint::BigInt x_stxo = Elements_TXO[0], x_txo = Elements_TXO[0];
        futures.push_back(threadPool_1.enqueue<void>([&, itr]() {
            RSAAccumulator::witnessesForSet(rep_txo, rsaKey, Wcc, threadPool_1);
        }));
        itr++;
        futures.push_back(threadPool_2.enqueue<void>([&, itr]() {
            RSAAccumulator::CreateNonMemWit(x_stxo, rep_stxo, rsaKey, prev_acc_stxo, dcc, bcc);
        }));
        for(auto& future:futures)
            future.get();
        itr = 0;
        futures.clear();

		//Updating Witnesses
		int step = 200;
        int len = 5;
        vector<double> time_boneh(len, 0.0), time_update_boneh(len, 0.0), time_proposed(len, 0.0), time_update_proposed(len, 0.0), time_minichain(len, 0.0), time_update_minichain(len, 0.0);
		flint::BigMod prev_wit = witnesses[0];
		flint::BigInt x_k = e_1[0];
        int MC_itr = 10;
        
        for(int mc=0;mc<MC_itr;mc++){
           for(int k=0;k<len;k++){

               cout << "\n/*-------------Iteration " << k+1 << " --------------*/" << endl;
               
               cout << "\n/*---------Boneh-----------------*/" << endl;
               // Batch Deletion
               flint::BigMod A_post_delete, A_, A_final, proof_D, W_, W;
               flint::BigInt p;
               vector<flint::BigMod>::size_type itr = 0;
	           
               // Let's deletes last 100 elements
               size_t elements_PREV_INPUTS = step*(k+1);
               size_t elements_PREV_OUTPUTS = step*(k+1);

               vector<flint::BigInt> x_list(elements_PREV_INPUTS);
               vector<flint::BigInt> y_list(elements_PREV_OUTPUTS);
               vector<flint::BigInt> reps_y(elements_PREV_OUTPUTS), reps_y_v(elements_PREV_OUTPUTS);
               vector<flint::BigMod> proofs_list(elements_PREV_INPUTS);
               
               flint::BigMod Q_A;
               for(size_t i=0;i<elements_PREV_INPUTS;i++){
                   x_list[i] = e_1[size  -1 - i];
                   proofs_list[i] = witnesses[size  - 1 - i];
               }
               for(size_t i=0;i<elements_PREV_OUTPUTS;i++)
                   y_list[i] = elements[size+i];

               double deleteStart = Profiler::getCurrentTime();
	           	RSAAccumulator::batch_delete_using_membership_proofs(acc, x_list, proofs_list, rsaKey.getPublicKey(), *(rsaKey.getPublicKey().primeRepGenerator),
                                                                        A_post_delete, p, proof_D, threadPool_1);
                   A_ = A_post_delete;
                   
                   RSAAccumulator::genRepresentatives(y_list, *(rsaKey.getPublicKey().primeRepGenerator), reps_y, threadPool_1);
                   RSAAccumulator::batchAdd(reps_y, rsaKey, A_, A_final, Q_A);
               double deleteEnd = Profiler::getCurrentTime();
               time_boneh[k] += (deleteEnd-deleteStart);
               
               cout << "\nDeleted "<< elements_PREV_INPUTS << " Members  in " << (deleteEnd-deleteStart) << " seconds with Proof generation." << endl;

	           // Update witness of a transaction
	           double start  = Profiler::getCurrentTime();
	           RSAAccumulator::witness_update_boneh(A_post_delete, prev_wit, x_list, y_list, x_k, rsaKey, W_, W, threadPool_1);
	           double end  = Profiler::getCurrentTime();
	           time_update_boneh[k] += (end - start);
	           bool b1, b2;
	           RSAAccumulator::verify(x_k, W_, A_post_delete, rsaKey.getPublicKey(), b1);
	           RSAAccumulator::verify(x_k, W, A_final, rsaKey.getPublicKey(), b2);
               cout << "\nTime consumed to update tx witness in Boneh " << time_update_boneh[k]/(mc+1) << endl; 
	           if(!(b1 && b2)) {
                   cout << "\nWitness for an element " << " did not pass!" << endl;
               }
               else
	           	cout << "Witness updated successfully!" << endl;
          

               prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
               prev_acc = rsaKey.getPublicKey().base;

               
               vector<flint::BigInt> elements_TXO, elements_STXO;
               flint::BigMod TXO_C, STXO_C, a, Q_TXO, Q_STXO, q_A;
               flint::BigMod new_d;
               flint::BigInt new_b;

               double updateStart, updateEnd;
               bool ans;

               size_t nSTXO = step*(k+1);
               size_t nTXO = step*(k+1);
               for(size_t j = size; j < size + nSTXO; j++)
                   elements_STXO.push_back(elements[j]);

               for(size_t j = size + nSTXO; j < size + nSTXO + nTXO; j++)
                   elements_TXO.push_back(elements[j+1000]);
               std::vector<flint::BigInt> rep_A(elements_STXO.size()), rep_STXO(elements_STXO.size()), rep_TXO(elements_TXO.size());
               cout << "\n/*---------Minichain--------------*/" << endl;
            
               // Minichain's witness update
               //double Start = Profiler::getCurrentTime();
               RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_A, threadPool_1);
               RSAAccumulator::batchAdd(rep_A, rsaKey, prev_acc, a, q_A);

               //double End = Profiler::getCurrentTime();
               //time_minichain[k] += (End - Start);
               flint::BigInt x_k = elements[20000];
               flint::BigMod d;
               flint::BigInt b;

               RSAAccumulator::CreateNonMemWit(x_k, rep_A, rsaKey, prev_acc, d, b);
               //bool ans;
               //RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, acc, prev_acc, d, b, ans);
               vector<flint::BigInt> e;
               for(size_t y = 0; y < step*(k+1); y++)
                   e.push_back(elements[y+10000]);
               //x_k = elements[2500];
               std::vector<flint::BigInt> reps_e(step*(k+1));//reps_e(size);
               RSAAccumulator::genRepresentatives(e, *(rsaKey.getPublicKey().primeRepGenerator),
                                                  reps_e, threadPool_1);           
               updateStart = Profiler::getCurrentTime();
                   RSAAccumulator::UpNonMemWit(x_k, d, b, reps_e, rsaKey, a, new_d, new_b); 
               updateEnd = Profiler::getCurrentTime();
               time_update_minichain[k] += (updateEnd - updateStart);
               cout << "\nTime consumed to update tx witness in Minichain " << time_update_minichain[k]/(mc+1) << endl;
               
               prev_acc = a;
               //flint::BigMod acc, Q;
               
               RSAAccumulator::batchAdd(reps_e, rsaKey, prev_acc, a, Q);
               prev_acc.setModulus(rsaKey.getPublicKey().rsaModulus);
               prev_acc = rsaKey.getPublicKey().base;
               RSAAccumulator::VerifyNonMemWit(x_k, rsaKey, a, prev_acc, new_d, new_b, ans);
           
               if(ans)
                   cout << "\nThe updated Witness in minichain verified successfully!" << endl;
               else
                   cout << "\nThe updated Witness in minichain not verified!!" << endl;

              cout << "\n/*---------CompactChain-----------------*/" << endl;
              // Proposed stateless blockchain's tx witness update
              itr = 0;
              futures.clear();
              RSAAccumulator::genRepresentatives(elements_TXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_TXO, threadPool_1);
              RSAAccumulator::genRepresentatives(elements_STXO, *(rsaKey.getPublicKey().primeRepGenerator),rep_STXO, threadPool_2);
              futures.push_back(threadPool_1.enqueue<void>([&, itr]() {
                  RSAAccumulator::batchAdd(rep_TXO, rsaKey, prev_acc, TXO_C, Q_TXO);
              }));
              itr++;
              futures.push_back(threadPool_2.enqueue<void>([&, itr]() {
                  RSAAccumulator::batchAdd(rep_STXO, rsaKey, prev_acc, STXO_C, Q_STXO);
              }));
              for(auto& future:futures)
                  future.get();
              itr = 0;
              futures.clear();
              vector<flint::BigMod> w(elements_TXO.size());
              RSAAccumulator::witnessesForSet(rep_TXO, rsaKey, w, threadPool_1);
              
              flint::BigInt x_m = elements_TXO[0];
              flint::BigMod w_m = w[0];
              
              vector<flint::BigInt> e_txo, e_stxo;
              // for(size_t k = 0; k < size; k++){
              for(size_t y = 0; y < step*(k+1); y++){
                  e_txo.push_back(elements[y+15000]);
                  e_stxo.push_back(elements[y+10000]);
              }
              
              std::vector<flint::BigInt> reps_e_txo(step*(k+1)), reps_e_stxo(step*(k+1));//reps_e_txo(size), reps_e_stxo(size);
              
              updateStart = Profiler::getCurrentTime();
                  RSAAccumulator::genRepresentatives(e_txo, *(rsaKey.getPublicKey().primeRepGenerator),
                                                 reps_e_txo, threadPool_1);
                  RSAAccumulator::genRepresentatives(e_stxo, *(rsaKey.getPublicKey().primeRepGenerator),
                                                 reps_e_stxo, threadPool_2);
                  futures.push_back(threadPool_1.enqueue<void>([&, itr]() {
                      // RSAAccumulator::genRepresentatives(e_txo, *(rsaKey.getPublicKey().primeRepGenerator), reps_e_txo, threadPool_1);
                      RSAAccumulator::UpMemWit(e_txo, rsaKey, threadPool_1, w_m);
                  }));
                  itr++;
                  futures.push_back(threadPool_2.enqueue<void>([&, itr]() {
                      // RSAAccumulator::genRepresentatives(e_stxo, *(rsaKey.getPublicKey().primeRepGenerator), reps_e_stxo, threadPool_2);
                      RSAAccumulator::UpNonMemWit(x_k, d, b, reps_e_stxo, rsaKey, STXO_C, new_d, new_b);
                  }));
                  for(auto& future:futures)
                      future.get();
              updateEnd = Profiler::getCurrentTime();
              time_update_proposed[k] += (updateEnd - updateStart);
              cout << "\nTime consumed to update tx witness in CompactChain " << time_update_proposed[k]/(mc + 1) << endl; 
              
              prev_acc = TXO_C;
              bool verifyPassed;

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
        }
    for (int k=0;k<len;k++){
        time_boneh[k] /= MC_itr;
        time_update_boneh[k] /= MC_itr;
        time_proposed[k] /= MC_itr;
        time_update_proposed[k] /= MC_itr;
        time_minichain[k] /= MC_itr;
        time_update_minichain[k] /= MC_itr;
    }
    std::ofstream file1, file2, file3;
    file1.open("./results/boneh/Data/testWitUp_result"+ index +".csv");
    file2.open("./results/minichain/Data/testWitUp_result"+ index +".csv");
    file3.open("./results/proposed/Data/testWitUp_result"+ index +".csv");
    
    file1 << "N,Time taken\n";
    file2 << "N,Time taken\n";
    file3 << "N,Time taken\n";
    cout << "\n/*-----------------Witness Update time-----------------------------*/" << endl;
    for(size_t i = 0; i < len; i++) {
        cout << "\n/*-----------Number of elements: " << (i+1)*step << " -----------------*/" << endl;
        cout << "Boneh accumulator update time : " << time_update_boneh.at(i) << " seconds" << endl;
        cout << "MiniChain accumulator update time : " << time_update_minichain.at(i) << " seconds" << endl;
        cout << "CompactChain accumulator update time : " << time_update_proposed.at(i) << " seconds" << endl;

        file1 << to_string((i+1)*step)+","+to_string(time_update_boneh.at(i))+"\n";
        file2 << to_string((i+1)*step)+","+to_string(time_update_minichain.at(i))+"\n";
        file3 << to_string((i+1)*step)+","+to_string(time_update_proposed.at(i))+"\n";
    }
    file1.close();
    file2.close();
    file3.close();
}

}  // namespace testWitUp
