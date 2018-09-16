#ifndef OT_IKNPOTEXTSENDER_H
#define OT_IKNPOTEXTSENDER_H

// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include <array>
#include "ot_ifc.h"

namespace osuCrypto {

    class IKNPSender :
        public OTExtSender
    {
    public: 
        std::array<PRNG, gOtExtBaseOtCount> mGens;
        BitVector mBaseChoiceBits;
        block mDelta;
        std::unique_ptr<OTExtSender> split() override;

        bool hasBaseOts() const override
        {
            return mBaseChoiceBits.size() > 0;
        }

        void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices) override;


        void send(
            span<std::array<block, 2>> in_data,
            PRNG& prng,
            Channel& chl/*,
            std::atomic<u64>& doneIdx*/) override;

        void set_delta(block delta);

    };
}

#endif
