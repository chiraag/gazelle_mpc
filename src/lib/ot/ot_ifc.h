#ifndef OT_OTEXTIFC_H
#define OT_OTEXTIFC_H


// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>
#include <array>
#ifdef GetMessage
#undef GetMessage
#endif


namespace osuCrypto
{

    // The hard coded number of base OT that is expected by the OT Extension implementations.
    // This can be changed if the code is adequately adapted. 
    const u64 gOtExtBaseOtCount(128);
    const u64 gCommStepSize(512);
    const u64 gSuperBlkSize(8);

    
    class BaseOTReceiver
    {
    public:
        BaseOTReceiver() {}
        virtual ~BaseOTReceiver(){};

        virtual void receive(
            const BitVector& choices,
            span<block> messages,
            PRNG& prng,
            Channel& chl) = 0;

    };

    class BaseOTSender
    {
    public:
        BaseOTSender() {}
        virtual ~BaseOTSender(){};

        virtual void send(
            span<std::array<block, 2>> messages,
            PRNG& prng,
            Channel& chl) = 0;

    };



    class OTExtReceiver
    {
    public:
        OTExtReceiver() {}
        virtual ~OTExtReceiver(){};

        virtual void setBaseOts(
            span<std::array<block,2>> baseSendOts) = 0;

        virtual bool hasBaseOts() const = 0; 
        virtual std::unique_ptr<OTExtReceiver> split() = 0;

        virtual void receive(
            const BitVector& choices,
            span<block> out_data,
            PRNG& prng,
            Channel& chl) = 0;

    };

    class OTExtSender
    {
    public:
        OTExtSender() {};
        virtual ~OTExtSender(){};

        virtual bool hasBaseOts() const = 0;

        virtual void setBaseOts(
            span<block> baseRecvOts,
            const BitVector& choices)  = 0;

        virtual std::unique_ptr<OTExtSender> split() = 0;

        virtual void send(
            span<std::array<block, 2>> in_data,
            PRNG& prng,
            Channel& chl) = 0;
    };

}

#endif
