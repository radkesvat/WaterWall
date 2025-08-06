//
// Created by 理 傅 on 2016/12/30.
//

#ifndef KCP_MATRIX_H
#define KCP_MATRIX_H

#include <vector>
#include <memory>
#include "galois.h"

using row_type = std::shared_ptr<std::vector<byte>>;

struct matrix {
    // newMatrix returns a matrix of zeros.
    static matrix newMatrix(int rows, int cols);

    // IdentityMatrix returns an identity matrix of the given empty.
    static matrix identityMatrix(int size);

    // Create a Vandermonde matrix, which is guaranteed to have the
    // property that any subset of rows that forms a square matrix
    // is invertible.
    static matrix vandermonde(int rows, int cols);

    // Multiply multiplies this matrix (the one on the left) by another
    // matrix (the one on the right) and returns a new matrix with the result.
    matrix Multiply(matrix &right);

    // Augment returns the concatenation of this matrix and the matrix on the right.
    matrix Augment(matrix &right);

    // Returns a part of this matrix. Data is copied.
    matrix SubMatrix(int rmin, int cmin, int rmax, int cmax);

    // IsSquare will return true if the matrix is square
    bool IsSquare();

    // SwapRows Exchanges two rows in the matrix.
    int SwapRows(int r1, int r2);

    // Invert returns the inverse of this matrix.
    // Returns ErrSingular when the matrix is singular and doesn't have an inverse.
    // The matrix must be square, otherwise ErrNotSquare is returned.
    matrix Invert();

    //  Gaussian elimination (also known as row reduction)
    int gaussianElimination();

    std::vector<row_type> data;
    int rows{0}, cols{0};

    inline byte &at(int row, int col) { return (*(data[row]))[col]; }

    inline bool empty() { return (rows == 0 || cols == 0); }
};


#endif //KCP_MATRIX_H
