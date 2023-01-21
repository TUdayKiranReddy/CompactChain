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
        size_t size = 2000;

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

        //cout << "\n/*---------Witnesses Creation-----------------*/" << endl;
        //// Witness Creation
        //vector<flint::BigMod> witnesses(size);
        //double memStart = Profiler::getCurrentTime();
        //RSAAccumulator::witnessesForSet(representatives, rsaKey.getPublicKey(), witnesses, threadPool);
        //double memEnd = Profiler::getCurrentTime();
        //cout << "\nGenerated "<< size << " Members witnesses in " << (memEnd-memStart) << " seconds with public key" << endl;
        
        cout << "\n/*---------Gennerate witnesses for all elements-----------------*/" << endl;
		//Generate witnesses for all of the representatives
		vector<flint::BigMod> witnesses(size);
		double witStart = Profiler::getCurrentTime();
		RSAAccumulator::witnessesForSet(representatives, rsaKey, witnesses, threadPool);
		double witEnd = Profiler::getCurrentTime();
		cout << "Generated " << witnesses.size() << " witnesses in " << (witEnd-witStart) << " seconds with private key" << endl;
		// cout << (witEnd - witStart) << endl;

		//Boneh's witness update
		int step = 200;
        int len = 5;
        vector<double> time_boneh, time_update_boneh, time_verify_boneh, time_proposed, time_verify_proposed;
		flint::BigMod prev_wit = witnesses[0];
		flint::BigInt x_k = e_1[0];

        std::ofstream file;
        file.open("./results/boneh/FinalWitUp.csv");
        file << "N, Average Time Taken\n";  

        for(int k=0;k<len;k++){
            cout << "\n/*---------Boneh Accumulator Update-----------------*/" << endl;
            cout << "Itr:- " << k << endl;
            // Batch Deletion
            flint::BigMod A_post_delete, A_, A_final, proof_D, W_, W;
            flint::BigInt p;
            vector<future<void>> futures;
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
                                                                     A_post_delete, p, proof_D, threadPool);
                A_ = A_post_delete;
                
                RSAAccumulator::genRepresentatives(y_list, *(rsaKey.getPublicKey().primeRepGenerator), reps_y, threadPool);
                RSAAccumulator::batchAdd(reps_y, rsaKey, A_, A_final, Q_A);
            double deleteEnd = Profiler::getCurrentTime();
            time_boneh.push_back(deleteEnd-deleteStart);
            
            cout << "\nDeleted "<< elements_PREV_INPUTS << " Members  in " << (deleteEnd-deleteStart) << " seconds with Proof generation." << endl;

			// Update witness of a transaction
			double start  = Profiler::getCurrentTime();
			RSAAccumulator::witness_update_boneh(A_post_delete, prev_wit, x_list, y_list, x_k, rsaKey, W_, W, threadPool);
			double end  = Profiler::getCurrentTime();
			time_update_boneh.push_back(end - start);
			bool b1, b2;
			RSAAccumulator::verify(x_k, W_, A_post_delete, rsaKey.getPublicKey(), b1);
			RSAAccumulator::verify(x_k, W, A_final, rsaKey.getPublicKey(), b2);
			if(!(b1 && b2)) {
                cout << "\nWitness for an element " << " did not pass!" << endl;
            }
            else
				cout << "witness updated successfully" << endl;
            cout << "\nTime taken :- " << time_update_boneh.at(k) << endl;
            file << (k+1)*step << "," << time_update_boneh.at(k) << "\n";
			
        }
    file.close();
    for(size_t i = 0; i < len; i++) {
        cout << "\n/*-----------Number of elements: " << (i+1)*step << " -----------------*/" << endl;
        cout << "Boneh accumulator update time : " << time_update_boneh.at(i) << " seconds" << endl;
        
	}
}

}  // namespace testproposed