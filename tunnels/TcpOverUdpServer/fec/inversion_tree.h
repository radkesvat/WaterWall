//
// Created by 理 傅 on 2017/1/1.
//

#ifndef KCP_INVERSION_TREE_H
#define KCP_INVERSION_TREE_H

#include <vector>
#include "matrix.h"

struct inversionNode {
    struct matrix m_matrix;
    std::vector<std::shared_ptr<inversionNode>> m_children;
    struct matrix getInvertedMatrix(std::vector<int> & invalidIndices, int parent);

    void insertInvertedMatrix(std::vector<int> &invalidIndices, struct matrix &matrix, int shards, int parent);
};

class inversionTree {
public:
    // newInversionTree initializes a tree for storing inverted matrices.
    // Note that the m_root node is the identity matrix as it implies
    // there were no errors with the original data.
    static inversionTree newInversionTree(int dataShards, int parityShards);

    // GetInvertedMatrix returns the cached inverted matrix or nil if it
    // is not found in the tree keyed on the indices of invalid rows.
    matrix GetInvertedMatrix(std::vector<int> & invalidIndices);

    // InsertInvertedMatrix inserts a new inverted matrix into the tree
    // keyed by the indices of invalid rows.  The total number of shards
    // is required for creating the proper length lists of child nodes for
    // each node.
    int InsertInvertedMatrix(std::vector<int> & invalidIndices, struct matrix &matrix, int shards);

private:
    inversionNode m_root;
};



#endif //KCP_INVERSION_TREE_H
