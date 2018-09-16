/*
encoding.h: This code implements packed integer encoding

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#ifndef LBCRYPTO_CRYPTO_ENCODING_H
#define LBCRYPTO_CRYPTO_ENCODING_H

#include "pke/pke_types.h"

namespace lbcrypto {

    void encoding_precompute(const ui64& mod_p, const ui32& logn);

    uv64 packed_encode(const uv64& input, const ui64 mod_p, const ui32 logn);

    uv64 packed_decode(const uv64& input, const ui64 mod_p, const ui32 logn);

} // namespace lbcrypto ends
#endif
