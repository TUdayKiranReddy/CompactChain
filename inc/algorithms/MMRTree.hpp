#include <fstream>
#include <iostream>
#include <vector>
#include <bits/stdc++.h>
#include <utils/LibConversions.hpp>

class Node{
public:
	int _level;
	std::vector<unsigned char> _hash;
	Node() {
        _level = -1;
        _hash.clear();
    }
    Node(int level, const std::vector<unsigned char>& hash) {
        _level = level;
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
	
	MMRTree();

	~MMRTree();

	void constructTree(const std::vector<std::vector<unsigned char>>& hashes, std::vector<std::vector<unsigned char>>& peaks);

	void updateTree(const std::vector<unsigned char> hash, std::vector<std::vector<unsigned char>>& peaks);

	void prove(const int index, std::vector<std::pair<std::vector<unsigned char>, bool>>& proof);

	void verify(const int index, const std::vector<std::pair<std::vector<unsigned char>, bool>>& proof, bool& isVerify);

	void printTree();

	int height;
	int _leafs;
	std::vector<int> leafs_positions;
private:
	std::vector<Node> tree;
	
	std::vector<Node> _peaks;
	std::vector<int> peaks_positions;

	void concat(const std::vector<unsigned char> lhash, const std::vector<unsigned char> rhash, std::vector<unsigned char>& output_digest);

	int getSiblingOffset(const int index);

	int isleftSibling_hasParent(const int index);

	void addNode(int& idx, int level, std::vector<unsigned char> hash);

	void addParent(int& idx);
};