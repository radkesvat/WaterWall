//
// Created by 理 傅 on 2017/1/1.
//

#include <iostream>
#include "inversion_tree.h"

inversionTree inversionTree::newInversionTree(int dataShards, int parityShards) {
    inversionTree tree;
    tree.m_root.m_children.resize(dataShards + parityShards, nullptr);
    tree.m_root.m_matrix = matrix::identityMatrix(dataShards);
    return tree;
}


matrix
inversionTree::GetInvertedMatrix(std::vector<int> &invalidIndices) {
    if (invalidIndices.size() == 0) {
        return m_root.m_matrix;
    }

    return m_root.getInvertedMatrix(invalidIndices, 0);
}

int
inversionTree::InsertInvertedMatrix(std::vector<int> &invalidIndices, matrix &matrix, int shards) {
    // If no invalid indices were given then we are done because the
    // m_root node is already set with the identity matrix.
    if (invalidIndices.size() == 0) {
        return -1;
    }

    if (!matrix.IsSquare()) {
        return -2;
    }

    // Recursively create nodes for the inverted matrix in the tree until
    // we reach the node to insert the matrix to.  We start by passing in
    // 0 as the parent index as we start at the m_root of the tree.
    m_root.insertInvertedMatrix(invalidIndices, matrix, shards, 0);

    return 0;
}

matrix
inversionNode::getInvertedMatrix(std::vector<int> &invalidIndices, int parent) {
    // Get the child node to search next from the list of m_children.  The
    // list of m_children starts relative to the parent index passed in
    // because the indices of invalid rows is sorted (by default).  As we
    // search recursively, the first invalid index gets popped off the list,
    // so when searching through the list of m_children, use that first invalid
    // index to find the child node.
    int firstIndex = invalidIndices[0];
    auto node = m_children[firstIndex - parent];

    // If the child node doesn't exist in the list yet, fail fast by
    // returning, so we can construct and insert the proper inverted matrix.
    if (node == nullptr) {
        return matrix{};
    }

    // If there's more than one invalid index left in the list we should
    // keep searching recursively.
    if (invalidIndices.size() > 1) {
        // Search recursively on the child node by passing in the invalid indices
        // with the first index popped off the front.  Also the parent index to
        // pass down is the first index plus one.
        std::vector<int> v(invalidIndices.begin() + 1, invalidIndices.end());
        return node->getInvertedMatrix(v, firstIndex + 1);
    }

    // If there aren't any more invalid indices to search, we've found our
    // node.  Return it, however keep in mind that the matrix could still be
    // nil because intermediary nodes in the tree are created sometimes with
    // their inversion matrices uninitialized.
    // std::cout << "return cached matrix:" << std::endl;
    return node->m_matrix;
}

void
inversionNode::insertInvertedMatrix(
        std::vector<int> &invalidIndices,
        struct matrix &matrix,
        int shards,
        int parent) {
    // As above, get the child node to search next from the list of m_children.
    // The list of m_children starts relative to the parent index passed in
    // because the indices of invalid rows is sorted (by default).  As we
    // search recursively, the first invalid index gets popped off the list,
    // so when searching through the list of m_children, use that first invalid
    // index to find the child node.
    int firstIndex = invalidIndices[0];
    auto node = m_children[firstIndex - parent];

    // If the child node doesn't exist in the list yet, create a new
    // node because we have the writer lock and add it to the list
    // of m_children.
    if (node == nullptr) {
        // Make the length of the list of m_children equal to the number
        // of shards minus the first invalid index because the list of
        // invalid indices is sorted, so only this length of errors
        // are possible in the tree.
        node = std::make_shared<inversionNode>();
        node->m_children.resize(shards - firstIndex, nullptr);
        m_children[firstIndex - parent] = node;
    }


    // If there's more than one invalid index left in the list we should
    // keep searching recursively in order to find the node to add our
    // matrix.
    if (invalidIndices.size() > 1) {
        // As above, search recursively on the child node by passing in
        // the invalid indices with the first index popped off the front.
        // Also the total number of shards and parent index are passed down
        // which is equal to the first index plus one.
        std::vector<int> v(invalidIndices.begin() + 1, invalidIndices.end());
        node->insertInvertedMatrix(v, matrix, shards, firstIndex + 1);
    } else {
        node->m_matrix = matrix;
    }
}