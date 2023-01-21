#include <fstream>
#include <iostream>

class Node{
public:
	int _level;
	long _hash;
	Node() {
        _level = -1;
        //_hash.clear();
        _hash = 0;
    }
    Node(int level, const std::vector<unsigned char>& hash) {
        _level = offset;
        _hash = hash;
    }
    Node& operator=(const Node& node) {
        if(this == &node) {
            return *this;
        }

        _level = node._level;
        _hash = node._hash;
        return *this;
    }
};

class MMRTree{
public:
	MMRTree() {
	}

	~MMRTree() {
		_tree.clear();
	}
	void constructTree(const std::vector<long>& hashes, std::vector<long>& peaks){
		int hashes_size = hashes.size();
		int temp = hashes_size;
		int tree_size=hashes_size;
		
		while(temp!=0){
			temp = temp >> 1;
			tree_size += temp;
		}

		tree.resize(tree_size);


	}

	void updateTree(const long hash, std::vector<long>& peaks){

	}

//private:
	int height;
	std::vector<Node> tree;
};