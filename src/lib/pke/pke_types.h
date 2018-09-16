/*
 * pke_types.h
 *
 *	Barebones data-structures
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */

#ifndef LBCRYPTO_CRYPTO_PUBKEYLP_H
#define LBCRYPTO_CRYPTO_PUBKEYLP_H

#include <vector>
#include "math/distrgen.h"


namespace lbcrypto {
    struct Ciphertext {
        uv64 a;
        uv64 b;

        Ciphertext(ui32 size) : a(size), b(size) {};
    };

    struct PublicKey {
        uv64 a;
        uv64 b;

        PublicKey(ui32 size) : a(size), b(size) {};
    };

    struct RelinKey {
        std::vector<uv64> a;
        std::vector<uv64> b;

        RelinKey(ui32 size, ui32 windows) : a(windows, uv64(size)), b(windows, uv64(size)) {};
    };


    struct SecretKey {
        uv64 s;

        SecretKey(ui32 size) : s(size) {};
    };

    struct KeyPair {
    public:
        PublicKey pk;
        SecretKey sk;

        KeyPair(const PublicKey& pk, const SecretKey& sk) : pk(pk), sk(sk) {};
    };

}
#endif
