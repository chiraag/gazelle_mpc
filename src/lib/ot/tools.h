#ifndef OT_TOOLS_H
#define OT_TOOLS_H

// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/MatrixView.h>
#include <wmmintrin.h>
namespace osuCrypto {

    void eklundh_transpose128(std::array<block, 128>& inOut);
    void sse_transpose128(std::array<block, 128>& inOut);
    void print(std::array<block, 128>& inOut);
    u8 getBit(std::array<block, 128>& inOut, u64 i, u64 j);

    void sse_transpose128x1024(std::array<std::array<block, 8>, 128>& inOut);

    void sse_transpose(const MatrixView<block>& in, const MatrixView<block>& out);
    //void sse_transpose_new(const MatrixView<u8>& in, const MatrixView<u8>& out);
    void sse_transpose(const MatrixView<u8>& in, const MatrixView<u8>& out);

}

#endif
