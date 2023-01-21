#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>
#include <math.h>

#include <algorithms/MMRTree.hpp>

#include <utils/Pointers.hpp>
#include <utils/Profiler.hpp>
#include <utils/ThreadPool.hpp>
#include <utils/LibConversions.hpp>

#include <flint/BigInt.hpp>
#include <flint/BigMod.hpp>
#include <flint/Random.hpp>

using namespace std;

namespace testMMRTree{
	vector<string> readSHA256(string filename);
	void string2vv_unsign_char(vector<string> elements, vector<vector<unsigned char>>& hashes);
	void printVector(vector<unsigned char>& v);
	void test(int setSize);
}

int main(){
	testMMRTree::test(100);
}

namespace testMMRTree{
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

	void test(int setSize){
		vector<string> Hhashes = readSHA256("randomSHA25610000");
	    vector<vector<unsigned char>> hashes;
	    string2vv_unsign_char(Hhashes, hashes);

	    int size = 100;
	    vector<vector<unsigned char>> e_1;
	    for(int i=0;i<size;i++)
	    	e_1.push_back(hashes[i]);

	    MMRTree mmr;
	    vector<vector<unsigned char>> prev_peaks;
	    mmr.constructTree(e_1, prev_peaks);
	    mmr.printTree();
	    int idx=size-1;

	    cout << "\n/-----------------Merkle Update--------------------/\n";
		int add_size = 2000;
		vector<Proof> proofs(add_size);

		double MerkleUpStart = Profiler::getCurrentTime();
		for(;idx<(size+add_size);idx++){
			mmr.updateTree(hashes[idx], prev_peaks);
		}
		for(int i=0;i<add_size;i++){
		    mmr.prove(i+size, proofs[i]);
		}
		double MerkleUpEnd = Profiler::getCurrentTime();
		cout << "\nTime taken for updating " << add_size << " with proof generation is " << (MerkleUpEnd-MerkleUpStart) << "s\n";

		bool isVerify = true;
		cout << "\n/-----------------Merkle Update Verification--------------------/\n";
		double MerkleVerStart = Profiler::getCurrentTime();
		for(int i=0;i<add_size;i++){
		    mmr.verify(i+size, proofs[i], isVerify);
			// if(isVerify)
			// 	std::cout << "MMR Inclusion Proof Succesfully Verfied at Index " << i+size <<"!\n";
			// else{
			// 	std::cout << "MMR Inclusion Proof Failed in Verification at Index " << i+size <<"!!\n";
			// 	// std::cout << "{";
			// 	// for(size_t j=0;j<proofs[i].size();j++){
			// 	// 	if(proofs[i][j].second)
			// 	// 		std::cout << "Right,";
			// 	// 	else
			// 	// 		std::cout << "Left,";
			// 	// }
			// 	// std::cout << "}\n";
			// }
		}
		double MerkleVerEnd = Profiler::getCurrentTime();
		if(isVerify)
			std::cout << "MMR Inclusion Proof Succesfully Verfied!\n";
		else
			std::cout << "MMR Inclusion Proof Failed in Verification!!\n";
		cout << "\nTime taken for Verification " << add_size << " is " << (MerkleVerEnd-MerkleVerStart) << "s\n";
	}

}