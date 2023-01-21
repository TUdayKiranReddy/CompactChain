#include <iostream>

#include <utils/LibConversions.hpp>
#include <utils/MerkleTree.hpp> 

using namespace std;

namespace MerkleAccumulator {
	void accumulate(const vector<vector<unsigned char> >& hashes, MerkleTree& tree){
		tree.constructTree(hashes);
	}

	void accumulateUpdate(int offset, const std::vector<unsigned char>& digest, MerkleTree& tree){
		tree.updateHash(offset, digest);
	}

	void proveHash(int index, const MerkleTree& tree, vector<HashNode>& hashes){
		tree.getHashes(index, hashes);
	}

	void verifyHash(const vector<HashNode>& hashes, const MerkleTree& tree, bool& isVerify){
		isVerify = tree.checkHashes(hashes);
	}
}