//
// Created by 理 傅 on 2016/12/30.
//

#ifndef KCP_MATRIX_H
#define KCP_MATRIX_H

#include "galois.h"
#include "ww_fec_allocator.h"
#include <memory>

using row_type = std::shared_ptr<FecVector<byte>>;

struct rs_matrix {
    // newMatrix returns a matrix of zeros.
    static rs_matrix newMatrix(int rows, int cols);

    // IdentityMatrix returns an identity matrix of the given empty.
    static rs_matrix identityMatrix(int size);

    // Create a Vandermonde matrix, which is guaranteed to have the
    // property that any subset of rows that forms a square matrix
    // is invertible.
    static rs_matrix vandermonde(int rows, int cols);

    // Multiply multiplies this matrix (the one on the left) by another
    // matrix (the one on the right) and returns a new matrix with the result.
    rs_matrix Multiply(rs_matrix &right);

    // Augment returns the concatenation of this matrix and the matrix on the right.
    rs_matrix Augment(rs_matrix &right);

    // Returns a part of this matrix. Data is copied.
    rs_matrix SubMatrix(int rmin, int cmin, int rmax, int cmax);

    // IsSquare will return true if the matrix is square
    bool IsSquare();

    // SwapRows Exchanges two rows in the matrix.
    int SwapRows(int r1, int r2);

    // Invert returns the inverse of this matrix.
    // Returns ErrSingular when the matrix is singular and doesn't have an inverse.
    // The matrix must be square, otherwise ErrNotSquare is returned.
    rs_matrix Invert();

    //  Gaussian elimination (also known as row reduction)
    int gaussianElimination();

    FecVector<row_type> data;
    int rows{0}, cols{0};

    inline byte &at(int row, int col) { return (*(data[row]))[col]; }

    inline bool empty() { return (rows == 0 || cols == 0); }
};


#endif //KCP_MATRIX_H
