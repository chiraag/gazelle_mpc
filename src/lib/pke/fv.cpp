/*
 * fv.cpp
 *
 *	This implementation is broadly similar to the PALISADE FV implementation
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */

#include <iostream>
#include <map>
#include <memory>
using std::shared_ptr;

#ifndef LBCRYPTO_CRYPTO_FV_C
#define LBCRYPTO_CRYPTO_FV_C

#include "math/params.h"
#include "math/transfrm.h"
#include "math/automorph.h"
#include "pke/encoding.h"
#include "pke/fv.h"

#include <iostream>

namespace lbcrypto {

std::map<ui32, shared_ptr<RelinKey>> g_rk_map;

uv64 NullEncrypt(uv64& pt, const FVParams& params){
    return ToEval(pt, params);
}

Ciphertext Encrypt(const PublicKey& pk, uv64& pt, const FVParams& params){
    uv64 u(params.phim);
    //Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
    if (params.mode == RLWE) {
        u = params.dgg->GenerateVector(params.phim, params.q);
    } else {
        u = get_tug_vector(params.phim, params.q);
    }
    u = ToEval(u, params);

    uv64 ea = ToEval(params.dgg->GenerateVector(params.phim, params.q), params);
    uv64 eb = params.dgg->GenerateVector(params.phim, params.q);

    Ciphertext ct(params.phim);
    for(ui32 i=0; i<params.phim; i++){
        ct.b[i] = pt[i]*params.delta + eb[i];
    }
    ct.b = ToEval(ct.b, params);

    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            ct.a[i] = opt::modq_full(opt::mul_modq_part(pk.a[i], u[i]) + ea[i]);
            ct.b[i] = opt::modq_full(opt::mul_modq_part(pk.b[i], u[i]) + ct.b[i]);
        } else {
            ct.a[i] = mod(mod_mul(pk.a[i], u[i], params.q) + ea[i], params.q);
            ct.b[i] = mod(mod_mul(pk.b[i], u[i], params.q) + ct.b[i], params.q);
        }
    }

    return ct;
}

Ciphertext Encrypt(const SecretKey& sk, uv64& pt, const FVParams& params){
    Ciphertext ct(params.phim);
    if(params.fast_modulli){
        ct.a = get_dug_vector_opt(params.phim);
    } else {
        ct.a = get_dug_vector(params.phim, params.q);
    }

    ct.b = params.dgg->GenerateVector(params.phim, params.q);
    for(ui32 i=0; i<params.phim; i++){
        ct.b[i] += pt[i]*params.delta;
    }
    ct.b = ToEval(ct.b, params);


    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            auto prod = opt::mul_modq_part(ct.a[i], sk.s[i]);
            ct.b[i] = opt::sub_modq_part(ct.b[i], prod);
        } else {
            auto prod = mod_mul(ct.a[i], sk.s[i], params.q);
            ct.b[i] = mod(ct.b[i] + params.q - prod, params.q);
        }
    }

    return ct;
}

uv64 Decrypt(const SecretKey& sk, const Ciphertext& ct, const FVParams& params){
    uv64 pt(params.phim);
    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            pt[i] = opt::mul_modq_part(ct.a[i], sk.s[i]) + ct.b[i];
        } else {
            pt[i] = mod_mul(ct.a[i], sk.s[i], params.q) + ct.b[i];
        }
    }
    pt = ToCoeff(pt, params);

    auto delta_by_2 = params.delta/2;
    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli) {
            pt[i] = opt::modq_full(pt[i]);
        }
        pt[i] = (pt[i] + delta_by_2)/params.delta;
    }

    return pt;
};

sv64 Noise(const SecretKey& sk, const Ciphertext& ct, const FVParams& params){
    uv64 e(params.phim);
    for(ui32 i=0; i<params.phim; i++){
        e[i] = mod_mul(ct.a[i], sk.s[i], params.q) + ct.b[i];
    }
    e = ToCoeff(e, params);

    sv64 es(params.phim);
    auto delta_by_2 = params.delta/2;
    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli) {
            e[i] = opt::modq_full(e[i]);
        }
        e[i] = (e[i] % params.delta);
        es[i] = (e[i] > delta_by_2) ? (e[i] - params.delta) : e[i];
    }

    return es;
};

double NoiseMargin(const SecretKey& sk, const Ciphertext& ct, const FVParams& params){
    sv64 noise = Noise(sk, ct, params);

    ui64 noise_max = 0;
    for(uint32_t i=0; i<params.phim; i++){
        ui64 noise_abs = std::abs(noise[i]);
        noise_max = std::max(noise_max, noise_abs);
    }

    return (std::log2(params.delta)-std::log2(noise_max));
}

KeyPair KeyGen(const FVParams& params){
    SecretKey sk(params.phim);

    if (params.mode == RLWE) {
        sk.s = params.dgg->GenerateVector(params.phim, params.q);
    } else {
        sk.s = get_tug_vector(params.phim, params.q);
    }
    sk.s = ToEval(sk.s, params);

    PublicKey pk(params.phim);
    if(params.fast_modulli){
        pk.a = get_dug_vector_opt(params.phim);
    } else {
        pk.a = get_dug_vector(params.phim, params.q);
    }
    pk.b = ToEval(params.dgg->GenerateVector(params.phim, params.q), params);

    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            auto prod = opt::mul_modq_part(pk.a[i], sk.s[i]);
            pk.b[i] = opt::sub_modq_part(pk.b[i], prod);
        } else {
            auto prod = mod_mul(pk.a[i], sk.s[i], params.q);
            pk.b[i] = mod(pk.b[i] + params.q - prod, params.q);
        }
    }

    return  KeyPair(pk, sk);
}

Ciphertext EvalAdd(const Ciphertext& ct1, const Ciphertext& ct2, const FVParams& params){
    Ciphertext sum(params.phim);

    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            sum.a[i] = opt::modq_part(ct1.a[i] + ct2.a[i]);
            sum.b[i] = opt::modq_part(ct1.b[i] + ct2.b[i]);
        } else {
            sum.a[i] = mod(ct1.a[i] + ct2.a[i], params.q);
            sum.b[i] = mod(ct1.b[i] + ct2.b[i], params.q);
        }
    }

    return sum;
}

Ciphertext EvalAddPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params){
    Ciphertext sum(params.phim);
    sum.a = ct.a;

    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            sum.b[i] = opt::modq_part(ct.b[i] + pt[i]);
        } else {
            sum.b[i] = mod(ct.b[i] + pt[i], params.q);
        }
    }

    return sum;
}

Ciphertext EvalSub(const Ciphertext& ct1, const Ciphertext& ct2, const FVParams& params){
    Ciphertext diff(params.phim);

    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            diff.a[i] = opt::sub_modq_part(ct1.a[i], ct2.a[i]);
            diff.b[i] = opt::sub_modq_part(ct1.b[i], ct2.b[i]);
        } else {
            diff.a[i] = mod(ct1.a[i] + params.q - ct2.a[i], params.q);
            diff.b[i] = mod(ct1.b[i] + params.q - ct2.b[i], params.q);
        }
    }

    return diff;
}

Ciphertext EvalSubPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params){
    Ciphertext diff(params.phim);
    diff.a = ct.a;

    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            diff.b[i] = opt::sub_modq_part(ct.b[i], pt[i]);
        } else {
            diff.b[i] = mod(ct.b[i] + params.q - pt[i], params.q);
        }
    }

    return diff;
}

Ciphertext EvalNegate(const Ciphertext& ct, const FVParams& params){
    Ciphertext neg(params.phim);

    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            neg.a[i] = opt::sub_modq_part(0, ct.a[i]);
            neg.b[i] = opt::sub_modq_part(0, ct.b[i]);
        } else {
            neg.a[i] = mod(params.q - ct.a[i], params.q);
            neg.b[i] = mod(params.q - ct.b[i], params.q);
        }
    }

    return neg;
}


Ciphertext EvalMultPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params){
    Ciphertext prod(params.phim);

    for(ui32 i=0; i<params.phim; i++){
        if(params.fast_modulli){
            prod.a[i] = opt::mul_modq_part(ct.a[i], pt[i]);
            prod.b[i] = opt::mul_modq_part(ct.b[i], pt[i]);
        } else {
            prod.a[i] = mod_mul(ct.a[i], pt[i], params.q);
            prod.b[i] = mod_mul(ct.b[i], pt[i], params.q);
        }
    }

    return prod;
}

RelinKey KeySwitchGen(const SecretKey& orig_sk, const SecretKey& new_sk, const FVParams& params){
    // This works because q is never a power of 2, so the floor is 1 less than size of q
    ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

    // Consider changing shape of rk for better locality
    RelinKey rk(params.phim, num_windows);

    for (ui32 i=0; i<num_windows; i++) {
        if(params.fast_modulli){
            rk.a[i] = get_dug_vector_opt(params.phim);
        } else {
            rk.a[i] = get_dug_vector(params.phim, params.q);
        }
        rk.b[i] = ToEval(params.dgg->GenerateVector(params.phim, params.q), params);

        for(ui32 j=0; j<params.phim; j++){
            if(params.fast_modulli){
                rk.b[i][j] += opt::lshift_modq_part(orig_sk.s[j], (i*params.window_size));
                auto prod = opt::mul_modq_part(rk.a[i][j], new_sk.s[j]);
                rk.b[i][j] = opt::sub_modq_part(rk.b[i][j], prod);
            } else {
                rk.b[i][j] += mod_mul((ui64)1 << (i*params.window_size), orig_sk.s[j], params.q);
                auto prod = mod_mul(rk.a[i][j], new_sk.s[j], params.q);
                rk.b[i][j] = mod(rk.b[i][j] + params.q - prod, params.q);
            }
        }
    }

    return rk;
}

std::vector<uv64> HoistedDecompose(const Ciphertext& ct, const FVParams& params){
    // This works because q is never a power of 2, so the floor is 1 less than size of q
    ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

    auto ct_a_coeff = ToCoeff(ct.a, params);
    if(params.fast_modulli){
        for(ui32 n=0; n<params.phim; n++){
            ct_a_coeff[n] = opt::modq_full(ct_a_coeff[n]);
        }
    }
    auto digits_ct = base_decompose(ct_a_coeff, params.window_size, num_windows);
    for(ui32 i=0; i<num_windows; i++){
        digits_ct[i] = ToEval(digits_ct[i], params);
    }

    return digits_ct;
}

Ciphertext KeySwitchDigits(const RelinKey& rk, const Ciphertext& ct,
        const std::vector<uv64> digits_ct, const FVParams& params){
    // This works because q is never a power of 2, so the floor is 1 less than size of q
    ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

    uv128 ct_a(params.phim);
    uv128 ct_b(ct.b.begin(), ct.b.end());

    for (ui32 i=0; i<num_windows; i++) {
        for (ui32 j=0; j<params.phim; j++){
            ct_a[j] += ((ui128)(digits_ct[i][j]) * (ui128)(rk.a[i][j]));
            ct_b[j] += ((ui128)(digits_ct[i][j]) * (ui128)(rk.b[i][j]));
        }
    }

    Ciphertext ct_new(params.phim);
    for (ui32 j=0; j<params.phim; j++){
        if(params.fast_modulli){
            ct_new.a[j] = opt::modq_part(ct_a[j]);
            ct_new.b[j] = opt::modq_part(ct_b[j]);
        } else {
            ct_new.a[j] = mod(ct_a[j], params.q);
            ct_new.b[j] = mod(ct_b[j], params.q);
        }
    }

    return ct_new;
}

Ciphertext KeySwitch(const RelinKey& rk, const Ciphertext& ct, const FVParams& params){
    auto digits_ct = HoistedDecompose(ct, params);
    return KeySwitchDigits(rk, ct, digits_ct, params);
}

Ciphertext EvalAutomorphismDigits(const ui32 rot, const RelinKey& rk, const Ciphertext& ct,
        const std::vector<uv64>& digits_ct, const FVParams& params){
    // This works because q is never a power of 2, so the floor is 1 less than size of q
    ui32 num_windows = 1 + floor(log2(params.q))/params.window_size;

    auto ct_b_rot = automorph(ct.b, rot);

    uv128 ct_a(params.phim);
    uv128 ct_b(ct_b_rot.begin(), ct_b_rot.end());

    for (ui32 i=0; i<num_windows; i++) {
        auto digit_rot = automorph(digits_ct[i], rot);
        for (ui32 j=0; j<params.phim; j++){
            ct_a[j] += ((ui128)(digit_rot[j]) * (ui128)(rk.a[i][j]));
            ct_b[j] += ((ui128)(digit_rot[j]) * (ui128)(rk.b[i][j]));
        }
    }

    Ciphertext ct_rot(params.phim);
    for (ui32 j=0; j<params.phim; j++){
        if(params.fast_modulli){
            ct_rot.a[j] = opt::modq_part(ct_a[j]);
            ct_rot.b[j] = opt::modq_part(ct_b[j]);
        } else {
            ct_rot.a[j] = mod(ct_a[j], params.q);
            ct_rot.b[j] = mod(ct_b[j], params.q);
        }
    }

    return ct_rot;
}

Ciphertext EvalAutomorphism(const ui32 rot, const Ciphertext& ct, const FVParams& params){
    const auto digits_ct = HoistedDecompose(ct, params);
    const auto rk = g_rk_map[rot];
    return EvalAutomorphismDigits(rot, (*rk), ct, digits_ct, params);
}

void EvalAutomorphismKeyGen(const SecretKey& sk,
    const uv32& index_list, const FVParams& params){
    for (ui32 i = 0; i < index_list.size(); i++){
        SecretKey sk_rot(params.phim);
        sk_rot.s = automorph(sk.s, index_list[i]);
        g_rk_map[index_list[i]] = std::make_shared<RelinKey>(KeySwitchGen(sk_rot, sk, params));
    }

    return;
}

shared_ptr<RelinKey> GetAutomorphismKey(ui32 rot){
    return g_rk_map[rot];
}

Ciphertext AddRandomNoise(const Ciphertext& ct, const FVParams& params){
    uv64 random_eval = get_dug_vector(params.phim, params.p);
    random_eval[0] = 0; //first plainext slot does not need to change

    uv64 random_coeff = packed_encode(random_eval, params.p, params.logn);

    Ciphertext random_ct(params.phim);
    random_ct.b = NullEncrypt(random_coeff, params);

    return EvalAdd(ct, random_ct, params);
};

/*
std::map<ui32, RelinKey> EvalSumKeyGen(const SecretKey& sk, const PublicKey& pk,
        const FVParams& params) {
    // stores automorphism indices needed for EvalSum
    uv32 indices;

    usint g = 5;
    for (int i = 0; i < params.logn - 1; i++) {
        indices.push_back(g);
        g = (g * g) % m;
    }
    indices.push_back(3);


    return EvalAutomorphismKeyGen(sk, indices, params);

}

Ciphertext EvalSum(const Ciphertext& ct,
        const std::map<ui32, RelinKey>& eval_keys, const FVParams& params) {

    Ciphertext result = ct;

    usint g = 5;
    for (int i = 0; i < params.logn - 1; i++) {
        result = EvalAdd(result, EvalAutomorphism(result, g, eval_keys, params));
        g = (g * g) % m;
    }
    result = EvalAdd(result, EvalAutomorphism(result, 3, evalKeys));

    return newCiphertext;

}

Ciphertext EvalInnerPlain(const Ciphertext& ct1, const Ciphertext& ct2,
    const std::map<ui32, RelinKey>& evalsum_keys, const FVParams& params) {

    Ciphertext result = EvalMultPlain(ct1, ct2, params);
    result = EvalSum(result, evalsum_keys, params);

    // add a random number to all slots except for the first one so that no information is leaked
    return AddRandomNoise(result, params);
}
*/


}  // namespace lbcrypto ends

#endif
