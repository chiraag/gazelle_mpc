#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Network/Channel.h>
#include <ot/cot_send.h>

#include "tools.h"

namespace osuCrypto
{
    using namespace std;




    std::unique_ptr<OTExtSender> IKNPSender::split()
    {

        std::unique_ptr<OTExtSender> ret(new IKNPSender());

        std::array<block, gOtExtBaseOtCount> baseRecvOts;

        for (u64 i = 0; i < mGens.size(); ++i)
        {
            baseRecvOts[i] = mGens[i].get<block>();
        }

        ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

        return std::move(ret);
    }

    void IKNPSender::setBaseOts(span<block> baseRecvOts, const BitVector & choices)
    {
        if (baseRecvOts.size() != gOtExtBaseOtCount || choices.size() != gOtExtBaseOtCount)
            throw std::runtime_error("not supported/implemented");

        mBaseChoiceBits = choices;
        for (u64 i = 0; i < gOtExtBaseOtCount; i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }
    }

    void IKNPSender::send(
        span<std::array<block, 2>> in_data,
        PRNG& prng,
        Channel& chl)
    {
        std::vector<std::array<block, 2>> out_data(in_data.size());

        // round up
        u64 numOtExt = roundUpTo(out_data.size(), 128);
        u64 numSuperBlocks = (numOtExt / 128 + gSuperBlkSize - 1) / gSuperBlkSize;
        //u64 numBlocks = numSuperBlocks * gSuperBlkSize;

        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, gSuperBlkSize>, 128> t;
        std::vector<std::array<block, gSuperBlkSize>> u(128 * gCommStepSize);

        std::array<block, 128> choiceMask;
        block delta = *(block*)mBaseChoiceBits.data();

        for (u64 i = 0; i < 128; ++i)
        {
            if (mBaseChoiceBits[i]) choiceMask[i] = AllOneBlock;
            else choiceMask[i] = ZeroBlock;
        }

        auto mIter = out_data.begin();

        block * uIter = (block*)u.data() + gSuperBlkSize * 128 * gCommStepSize;
        block * uEnd = uIter;

        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {


            block * tIter = (block*)t.data();
            block * cIter = choiceMask.data();

            if (uIter == uEnd)
            {
                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)gCommStepSize);

                chl.recv((u8*)u.data(), step * gSuperBlkSize * 128 * sizeof(block));
                uIter = (block*)u.data();
            }

            // transpose 128 columns at at time. Each column will be 128 * gSuperBlkSize = 1024 bits long.
            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the columns using AES-NI in counter mode.
                mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, gSuperBlkSize, tIter);
                mGens[colIdx].mBlockIdx += gSuperBlkSize;

                uIter[0] = uIter[0] & *cIter;
                uIter[1] = uIter[1] & *cIter;
                uIter[2] = uIter[2] & *cIter;
                uIter[3] = uIter[3] & *cIter;
                uIter[4] = uIter[4] & *cIter;
                uIter[5] = uIter[5] & *cIter;
                uIter[6] = uIter[6] & *cIter;
                uIter[7] = uIter[7] & *cIter;

                tIter[0] = tIter[0] ^ uIter[0];
                tIter[1] = tIter[1] ^ uIter[1];
                tIter[2] = tIter[2] ^ uIter[2];
                tIter[3] = tIter[3] ^ uIter[3];
                tIter[4] = tIter[4] ^ uIter[4];
                tIter[5] = tIter[5] ^ uIter[5];
                tIter[6] = tIter[6] ^ uIter[6];
                tIter[7] = tIter[7] ^ uIter[7];

                ++cIter;
                uIter += 8;
                tIter += 8;
            }

            // transpose our 128 columns of 1024 bits. We will have 1024 rows,
            // each 128 bits wide.
            sse_transpose128x1024(t);


            auto mEnd = mIter + std::min<u64>(128 * gSuperBlkSize, out_data.end() - mIter);

            tIter = (block*)t.data();
            block* tEnd = (block*)t.data() + 128 * gSuperBlkSize;

            while (mIter != mEnd)
            {
                while (mIter != mEnd && tIter < tEnd)
                {
                    (*mIter)[0] = *tIter;
                    (*mIter)[1] = *tIter ^ delta;

                    tIter += gSuperBlkSize;
                    mIter += 1;
                }

                tIter = tIter - 128 * gSuperBlkSize + 1;
            }


#ifdef IKNP_DEBUG
            BitVector choice(128 * gSuperBlkSize);
            chl.recv(u.data(), gSuperBlkSize * 128 * sizeof(block));
            chl.recv(choice.data(), sizeof(block) * gSuperBlkSize);

            u64 doneIdx = mStart - out_data.data();
            u64 xx = std::min<u64>(i64(128 * gSuperBlkSize), (out_data.data() + out_data.size()) - mEnd);
            for (u64 rowIdx = doneIdx,
                j = 0; j < xx; ++rowIdx, ++j)
            {
                if (neq(((block*)u.data())[j], out_data[rowIdx][choice[j]]))
                {
                    std::cout << rowIdx << std::endl;
                    throw std::runtime_error("");
                }
            }
#endif
        }

#ifdef IKNP_SHA_HASH
        SHA1 sha;
        u8 hashBuff[20];
        u64 doneIdx = 0;


        u64 bb = (out_data.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            u64 stop = std::min<u64>(out_data.size(), doneIdx + 128);

            for (u64 i = 0; doneIdx < stop; ++doneIdx, ++i)
            {
                // hash the message without delta
                sha.Reset();
                sha.Update((u8*)&out_data[doneIdx][0], sizeof(block));
                sha.Final(hashBuff);
                out_data[doneIdx][0] = *(block*)hashBuff;

                // hash the message with delta
                sha.Reset();
                sha.Update((u8*)&out_data[doneIdx][1], sizeof(block));
                sha.Final(hashBuff);
                out_data[doneIdx][1] = *(block*)hashBuff;
            }
        }
#else


        std::array<block, 8> aesHashTemp;

        u64 doneIdx = 0;
        u64 bb = (out_data.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            u64 stop = std::min<u64>(out_data.size(), doneIdx + 128);

            auto length = 2 * (stop - doneIdx);
            auto steps = length / 8;
            block* mIter = out_data[doneIdx].data();
            for (u64 i = 0; i < steps; ++i)
            {
                mAesFixedKey.ecbEncBlocks(mIter, 8, aesHashTemp.data());
                mIter[0] = mIter[0] ^ aesHashTemp[0];
                mIter[1] = mIter[1] ^ aesHashTemp[1];
                mIter[2] = mIter[2] ^ aesHashTemp[2];
                mIter[3] = mIter[3] ^ aesHashTemp[3];
                mIter[4] = mIter[4] ^ aesHashTemp[4];
                mIter[5] = mIter[5] ^ aesHashTemp[5];
                mIter[6] = mIter[6] ^ aesHashTemp[6];
                mIter[7] = mIter[7] ^ aesHashTemp[7];

                mIter += 8;
            }

            auto rem = length - steps * 8;
            mAesFixedKey.ecbEncBlocks(mIter, rem, aesHashTemp.data());
            for (u64 i = 0; i < rem; ++i)
            {
                mIter[i] = mIter[i] ^ aesHashTemp[i];
            }

            doneIdx = stop;
        }

#endif

        u64 CommSize = std::min<u64>((u64)gCommStepSize * 128 * gSuperBlkSize, out_data.size());
        std::vector<block> uBuff(2*CommSize);
        u64 numFlights = (out_data.size() + CommSize - 1)/CommSize;

        u64 nbase = 0;
        u64 currSize = CommSize;
        for (u64 f = 0; f < numFlights; ++f)
        {
            for (u64 n = 0; n < currSize; ++n)
            {
                uBuff[2*n] = out_data[nbase][0] ^ in_data[nbase][0];
                uBuff[2*n+1] = out_data[nbase][1] ^ in_data[nbase][1];
                nbase++;
            }
            chl.asyncSend(std::move(uBuff));

            currSize = std::min<u64>(CommSize, out_data.size() - nbase);
            uBuff.resize(2*currSize);
        }

        static_assert(gOtExtBaseOtCount == 128, "expecting 128");
    }

}
