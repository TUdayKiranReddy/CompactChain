#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>
#include <math.h>

#include <algorithms/MerkleAccumulator.hpp>

#include <utils/Pointers.hpp>
#include <utils/Profiler.hpp>
#include <utils/ThreadPool.hpp>
#include <utils/LibConversions.hpp>

#include <flint/BigInt.hpp>
#include <flint/BigMod.hpp>
#include <flint/Random.hpp>

using namespace std;

namespace testMerkle {
	vector<string> readSHA256(string filename);
	void string2vv_unsign_char(vector<string> elements, vector<vector<unsigned char>>& hashes);
}

void printVector(vector<unsigned char>& v){
	for(size_t i=0;i<v.size();i++)
		cout << v[i];
	cout <<"\n";
}

int main(){
    vector<string> Hhashes = testMerkle::readSHA256("randomSHA25610000");
    vector<vector<unsigned char>> hashes;
    testMerkle::string2vv_unsign_char(Hhashes, hashes);
    // for(size_t i =0;i<hashes.size();i++){
    // 	printVector(hashes[i]);
    // }
    int size = 300;
    int add_size = 100;
    vector<vector<unsigned char>> e_1;
    for(int i=0;i<size;i++)
    	e_1.push_back(hashes[i]);
    cout << "Yo1\n"; 
    MerkleTree prev_tree;
    MerkleAccumulator::accumulate(e_1, prev_tree);

    vector<vector<HashNode>> proof(size);
    bool isVerify;

   	vector<vector<unsigned char>> e_2;
    for(int i=size;i<size+add_size;i++)
    	e_2.push_back(hashes[i]);
    cout << "Yo\n"; 
    double MerkelUpstart = Profiler::getCurrentTime();
	    for(int i=0;i<add_size;i++){
	    	cout << "Itr:- " << i;
		    MerkleAccumulator::accumulateUpdate(0, e_2[i], prev_tree);
		    cout << " Update Done ";
		    MerkleAccumulator::proveHash(size+i, prev_tree, proof[i]);
		    cout << " Proof Done\n";
		}
 	double MerkelUpend = Profiler::getCurrentTime();
 	cout << "Time for " << size << " updates with MerkleAccumulator is " << MerkelUpend-MerkelUpstart << endl;
 	double MerkelVerstart = Profiler::getCurrentTime();
		for(int i=0;i<add_size;i++){
	    	MerkleAccumulator::verifyHash(proof[i], prev_tree, isVerify);
            cout << "Itr:- " << i << " ";
	    	if(isVerify)
	    		cout << "Merkle Proof verified!\n";
	    	else
	    		cout << "Merkle proof not verified!!\n";
		}
    double MerkelVerend = Profiler::getCurrentTime();
    cout << "Time for " << size << " verifications with MerkleAccumulator is " << MerkelVerend-MerkelVerstart << endl;
    // if(isVerify)
    // 	cout << "Hash at index 10 Verified!\n";
   	// else
   	// 	cout << "Hash at index 10 not Verified!!";
}
namespace testMerkle {

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

	void test(int setSize){
		
	}
}