/*
 * transform.cpp
 *
 *	An initial draft of the transform code is inspired from my experiments with
 *	the PALISADE transform code.
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */

#include "transfrm.h"
#include "bit_twiddle.h"
#include "math/params.h"

namespace lbcrypto {
    std::map<ui64, uv64> g_rootOfUnityMap;
    std::map<ui64, uv64> g_rootOfUnityInverseMap;
    std::map<ui64, uv64> g_scaledInverseMap;
    std::map<ui64, uv32> g_reverseMap;

    //Number Theoretic Transform - ITERATIVE IMPLEMENTATION -  twiddle factor table precomputed
    uv64 ntt_fwd(const uv64& element,
            const uv64 &rootOfUnityTable, const ui64 modulus,
            const ui32 logn) {
        ui32 phim = (1 << logn);
        uv64 result(phim);
        const auto& reverse_id = g_reverseMap[modulus];


        //reverse coefficients (bit reversal)
        for (ui32 i = 0; i < phim; i++){
            result[i] = element[reverse_id[i]];
        }

        ui64 omegaFactor;
        ui64 butterflyPlus;
        ui64 butterflyMinus;

        for (ui32 logm = 1; logm <= logn; logm++)
        {
            for (ui32 j = 0; j<phim; j = j + (1 << logm))
            {
                for (ui32 i = 0; i < (ui32)(1 << (logm-1)); i++)
                {

                    ui32 x = (i << (1+logn-logm));

                    ui64 omega = rootOfUnityTable[x];

                    ui32 indexEven = j + i;
                    ui32 indexOdd = j + i + (1 << (logm-1));

                    if (result[indexOdd] != 0)
                    {
                        if (result[indexOdd] == 1){
                            omegaFactor = omega;
                        } else {
                            omegaFactor = mod_mul(omega, result[indexOdd], modulus);
                        }

                        // Potential overflow issue analyze carefully
                        // butterflyPlus = result[indexEven] + omegaFactor;
                        // butterflyMinus = result[indexEven] + modulus - omegaFactor;

                        // No overflow
                        butterflyPlus = result[indexEven];
                        butterflyPlus += omegaFactor;
                        if (butterflyPlus >= modulus)
                            butterflyPlus -= modulus;

                        butterflyMinus = result[indexEven];
                        if (result[indexEven] < omegaFactor)
                            butterflyMinus += modulus;
                        butterflyMinus -= omegaFactor;

                        result[indexEven] = butterflyPlus;
                        result[indexOdd] = butterflyMinus;
                    } else {
                          result[indexOdd] = result[indexEven];
                    }
                }

            }
        }

        return result;
    }

    //main Forward CRT Transform - implements FTT - uses iterative NTT as a subroutine
    uv64 ftt_fwd(const uv64& element,
            const ui64 modulus, const ui32 logn) {
        auto mSearch = g_rootOfUnityMap.find(modulus);
        if(mSearch == g_rootOfUnityMap.end()) {
            throw std::logic_error("Root of Unity table must be precomputed");
        }

        ui32 phim = (1<<logn);
        uv64 InputToFFT(phim, 0);
        for (ui32 i = 0; i<phim; i++)
            InputToFFT[i] = mod_mul(element[i], g_rootOfUnityMap[modulus][i], modulus);

        auto OpFFT = ntt_fwd(InputToFFT, g_rootOfUnityMap[modulus], modulus, logn);

        return OpFFT;
    }

    //main Inverse CRT Transform - implements FTT - uses iterative NTT as a subroutine
    uv64 ftt_inv(const uv64& element,
            const ui64 modulus, const ui32 logn) {
        ui32 phim = (1<<logn);
        auto mSearch = g_rootOfUnityInverseMap.find(modulus);
        if(mSearch == g_rootOfUnityInverseMap.end()) {
            throw std::logic_error("Root of Unity table must be precomputed");
        }

        auto OpIFFT = ntt_fwd(element, g_rootOfUnityInverseMap[modulus], modulus, logn);

        for (ui32 i=0; i<phim; i++){
            OpIFFT[i] = mod_mul(OpIFFT[i], g_scaledInverseMap[modulus][i], modulus);
        }

        return OpIFFT;
    }

    uv64 inline ntt_fwd_opt(const uv64& element, const uv64& rootOfUnityTable) {
        ui32 phim = opt::phim;
        ui32 logn = opt::logn;
        const auto& reverse_id = g_reverseMap[opt::q];

        //reverse coefficients (bit reversal)
        uv64 result(phim);
        for (ui32 i = 0; i < phim; i++)
            result[i] = element[reverse_id[i]];

        ui64 resultP;
        ui64 omegaFactor;

        for (ui32 logm = 1; logm <= logn; logm++)
        {
            for (ui32 j = 0; j<phim; j = j + (1 << logm))
            {
                for (ui32 i = 0; i < ((ui32)1 << (logm-1)); i++)
                {
                    ui32 x = (i << (1+logn-logm));
                    const ui64& omega = rootOfUnityTable[x];

                    ui32 indexEven = j + i;
                    ui32 indexOdd = j + i + (1 << (logm-1));

                    if (result[indexOdd] != 0){
                        omegaFactor = opt::mul_modq_part(omega, result[indexOdd]);
                        resultP = opt::modq_part(result[indexEven]);
                        result[indexEven] = (resultP + omegaFactor);
                        result[indexOdd] = (resultP + opt::q4 - omegaFactor);
                    } else {
                      result[indexOdd] = result[indexEven];
                    }

                }

            }
        }

        return result;
    }

    uv64 ftt_fwd_opt(const uv64& input){
        ui32 phim = opt::phim;
        const auto& rootOfUnityTable = g_rootOfUnityMap[opt::q];

        uv64 element(phim);
        for (ui32 i = 0; i<phim; i++)
            element[i] = opt::mul_modq_part(input[i], rootOfUnityTable[i]);

        return ntt_fwd_opt(element, rootOfUnityTable);
    }

    uv64 ftt_inv_opt(const uv64& input){
        ui32 phim = opt::phim;
        const auto& rootOfUnityInverseTable = g_rootOfUnityInverseMap[opt::q];
        const auto& scaledInverseTable = g_scaledInverseMap[opt::q];

        //reverse coefficients (bit reversal)
        uv64 result(phim);
        result = ntt_fwd_opt(input, rootOfUnityInverseTable);

        uv64 element(phim);
        for (ui32 i = 0; i<phim; i++)
            element[i] = opt::mul_modq_part(result[i], scaledInverseTable[i]);

        return element;
    }

    uv64 inline ntt_fwd_opt_p(const uv64& element, const uv64& rootOfUnityTable) {
        ui32 phim = opt::phim;
        ui32 logn = opt::logn;
        const auto& reverse_id = g_reverseMap[opt::p];

        //reverse coefficients (bit reversal)
        uv64 result(phim);
        for (ui32 i = 0; i < phim; i++)
            result[i] = element[reverse_id[i]];

        ui64 resultP;
        ui64 omegaFactor;

        for (ui32 logm = 1; logm <= logn; logm++)
        {
            for (ui32 j = 0; j<phim; j = j + (1 << logm))
            {
                for (ui32 i = 0; i < ((ui32)1 << (logm-1)); i++)
                {
                    ui32 x = (i << (1+logn-logm));
                    const ui64& omega = rootOfUnityTable[x];

                    ui32 indexEven = j + i;
                    ui32 indexOdd = j + i + (1 << (logm-1));

                    if (result[indexOdd] != 0){
                        omegaFactor = opt::modp_part(omega*result[indexOdd]);
                        resultP = opt::modp_part(result[indexEven]);
                        result[indexEven] = (resultP + omegaFactor);
                        result[indexOdd] = (resultP + opt::p2 - omegaFactor);
                    } else {
                      result[indexOdd] = result[indexEven];
                    }

                }

            }
        }

        return result;
    }

    uv64 ftt_fwd_opt_p(const uv64& input){
        ui32 phim = opt::phim;
        const auto& rootOfUnityTable = g_rootOfUnityMap[opt::p];

        uv64 element(phim);
        for (ui32 i = 0; i<phim; i++)
            element[i] = opt::modp_part(input[i] * rootOfUnityTable[i]);

        element = ntt_fwd_opt_p(element, rootOfUnityTable);
        for (ui32 i = 0; i<phim; i++)
            element[i] = opt::modp_full(element[i]);

        return element;
    }

    uv64 ftt_inv_opt_p(const uv64& input){
        ui32 phim = opt::phim;
        const auto& rootOfUnityInverseTable = g_rootOfUnityInverseMap[opt::p];
        const auto& scaledInverseTable = g_scaledInverseMap[opt::p];

        //reverse coefficients (bit reversal)
        uv64 result(phim);
        result = ntt_fwd_opt_p(input, rootOfUnityInverseTable);

        uv64 element(phim);
        for (ui32 i = 0; i<phim; i++)
            element[i] = opt::modp_full(result[i]*scaledInverseTable[i]);

        return element;
    }

    void ftt_precompute(const ui64 rootOfUnity, const ui64 modulus,  const ui32 logn) {
        ui32 phim = (1<<logn);

        //Precomputes twiddle factor omega and FTT parameter phi for Forward Transform
        ui64 x(1);

        uv64 table(phim);
        for (ui32 i = 0; i<phim; i++) {
            table[i] = x;
            x = mod_mul(x, rootOfUnity, modulus);
        }
        g_rootOfUnityMap[modulus] = std::move(table);

        //Precomputes twiddle factor omega and FTT parameter phi for Inverse Transform
        x = 1;
        ui64 rootOfUnityInverse = mod_inv(rootOfUnity, modulus);

        uv64  table_inv(phim);
        for (ui32 i = 0; i<phim; i++) {
            table_inv[i] = x;
            x = mod_mul(x, rootOfUnityInverse, modulus);
        }
        g_rootOfUnityInverseMap[modulus] = std::move(table_inv);

        ui64 modulus_inv = mod_inv(phim, modulus);
        uv64  table_scaled_inv(phim);
        for (ui32 i = 0; i<phim; i++) {
            table_scaled_inv[i] = mod_mul(modulus_inv, g_rootOfUnityInverseMap[modulus][i], modulus);
        }
        g_scaledInverseMap[modulus] = std::move(table_scaled_inv);

        uv32  reverse_id(phim);
        for (ui32 i = 0; i < phim; i++){
            reverse_id[i] = ReverseBits(i, logn);
        }
        g_reverseMap[modulus] = std::move(reverse_id);

    }


    void ftt_pre_compute(const uv64& rootsOfUnity, const uv64& moduliiChain, const ui32 logn) {
        ui32 numOfRootU = rootsOfUnity.size();
        ui32 numModulii = moduliiChain.size();

        if (numOfRootU != numModulii) {
            throw std::logic_error("size of root of unity and size of moduli chain not of same size");
        }

        for (ui32 i = numOfRootU; i<numOfRootU; ++i) {
            ftt_precompute(rootsOfUnity[i], moduliiChain[i], logn);
        }
    }

}//namespace ends here
