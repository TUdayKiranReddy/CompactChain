#ifndef _MMR_TREE_H_
#define _MMR_TREE_H_


#include <fstream>
#include <iostream>

class Node{
public:
	int _level;
	long _hash;
};


class MMRTree{
public:
	void constructTree(const std::vector<long>& hashes, std::vector<long>& peaks);

	void updateTree(const long hash, std::vector<long>& peaks);

//private:
	int height;
	std::vector<Node> tree;
};

#endif /* _MMR_TREE_H_ */
