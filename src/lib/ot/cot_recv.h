#ifndef OT_IKNPOTEXTRECV_H
#define OT_IKNPOTEXTRECV_H

// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <array>
#include "ot_ifc.h"

namespace osuCrypto
{

    class IKNPReceiver :
        public OTExtReceiver
    {
    public:
        IKNPReceiver()
            :mHasBase(false)
        {}

        bool hasBaseOts() const override
        {
            return mHasBase;
        }

        bool mHasBase;
        std::array<std::array<PRNG, 2>, gOtExtBaseOtCount> mGens;

        void setBaseOts(
            span<std::array<block, 2>> baseSendOts)override;
        std::unique_ptr<OTExtReceiver> split() override;


        void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl
        ) override;

    };

}

#endif
