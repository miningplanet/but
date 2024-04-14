// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util.h>

#include <math.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params, int algo) {
    unsigned int npowWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == nullptr)
        return npowWorkLimit;

    // find first block in averaging interval
    // Go back by what we want to be nAveragingInterval blocks per algo
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < NUM_ALGOS * params.nAveragingInterval; i++)
    {
        pindexFirst = pindexFirst->pprev;
    }

    const CBlockIndex* pindexPrevAlgo = GetLastBlockIndexForAlgo(pindexLast, params, algo);
    if (pindexPrevAlgo == nullptr || pindexFirst == nullptr || params.fPowNoRetargeting)
    {
        return npowWorkLimit;
    }

    // Limit adjustment step
    // Use medians to prevent time-warp attacks
    int64_t nActualTimespan = pindexLast->GetMedianTimePast() - pindexFirst->GetMedianTimePast();
    nActualTimespan = params.nAveragingTargetTimespan + (nActualTimespan - params.nAveragingTargetTimespan) / 4;

    if (nActualTimespan < params.nMinActualTimespan)
        nActualTimespan = params.nMinActualTimespan;
    if (nActualTimespan > params.nMaxActualTimespan)
        nActualTimespan = params.nMaxActualTimespan;

    //Global retarget
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrevAlgo->nBits);

    bnNew *= nActualTimespan;
    bnNew /= params.nAveragingTargetTimespan;

    //Per-algo retarget
    int nAdjustments{0};
    nAdjustments = pindexPrevAlgo->nHeight + NUM_ALGOS - 1 - pindexLast->nHeight;
    const auto powLimit = UintToArith256(params.powLimit);
    const auto multiplicator = 100 + params.nLocalTargetAdjustment;

    
    // Done by ChatGPT 3.5
    // if (nAdjustments > 0) {
    //     int64_t factor = static_cast<int64_t>(std::pow(multiplicator, nAdjustments));
    //     int64_t denominator = static_cast<int64_t>(std::pow(100, nAdjustments));
    //     bnNew = (bnNew * factor) / denominator;
    // } else if (nAdjustments < 0) {
    //     int64_t power = -nAdjustments;
    //     int64_t factor = static_cast<int64_t>(std::pow(104, power));
    //     int64_t denominator = static_cast<int64_t>(std::pow(100, power));
    //     bnNew = (bnNew * factor) / denominator;
    // }
    if (nAdjustments > 0)
    {
        for (int i = 0; i < nAdjustments; i++)
        {
            if (bnNew > powLimit) {
                bnNew = powLimit;
                // return bnNew.GetCompact();
                break;
            }
            bnNew *= 100;
            bnNew /= multiplicator;
        }
    }
    if (nAdjustments < 0)
    {
        for (int i = 0; i < -nAdjustments; i++)
        {
            if (bnNew > powLimit) {
                bnNew = powLimit;
                // return bnNew.GetCompact();
                break;
            }
            bnNew *= multiplicator;
            bnNew /= 100;
        }
    }

     // Double check.
    if (bnNew > powLimit) {
        bnNew = powLimit;
    }

    const uint32_t result = bnNew.GetCompact();
    LogPrintf("Calc next work (adjust=%d, powLimit=%d): %d\n", nAdjustments, powLimit.GetCompact(), result);
    return result;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

const CBlockIndex* GetLastBlockIndexForAlgo(const CBlockIndex* pindex, const Consensus::Params& params, int algo)
{
    for (; pindex; pindex = pindex->pprev)
    {
        if (pindex->GetAlgo() != algo)
            continue;
        // ignore special min-difficulty testnet blocks
        if (params.fPowAllowMinDifficultyBlocks &&
            pindex->pprev &&
            pindex->nTime > pindex->pprev->nTime + params.nPowTargetSpacing*6)
        {
            continue;
        }
        return pindex;
    }
    return nullptr;
}

unsigned int GetAlgoWeight(int algo)
{
    switch (algo)
    {
        case ALGO_SHA256D:
            return (unsigned int)(0.005 * 100000);
        case ALGO_YESPOWER:
            return (unsigned int)(0.00015 * 100000);
        case ALGO_GHOSTRIDER:
            return (unsigned int)(6 * 100000);
        case ALGO_LYRA2:
            return (unsigned int)(6 * 100000);
        case ALGO_BUTKSCRYPT:
            return (unsigned int)(1.4 * 100000);
        case ALGO_SCRYPT:
            return (unsigned int)(1.2 * 100000);
        default: // Lowest
            printf("GetAlgoWeight(): can't find algo %d", algo);
            return (unsigned int)(0.00015 * 100000);
    }
}
