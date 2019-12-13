// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2014-2019 The DigiByte Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <chainparams.h>

#include "util.h" //just for logs

inline unsigned int PowLimit(const Consensus::Params& params)
{
    return UintToArith256(params.powLimit).GetCompact();
}

unsigned int InitialDifficulty(const Consensus::Params& params, int algo)
{
    const auto& it = params.initialTarget.find(algo);
    if (it == params.initialTarget.end())
        return PowLimit(params);
    return UintToArith256(it->second).GetCompact();
}

unsigned int GetNextWorkRequired_Original(const CBlockIndex* pindexLast, const Consensus::Params& params, int algo)
{
      unsigned int nProofOfWorkLimit = InitialDifficulty(params, algo);
      const int nTargetTimespan =  4800;
      const int nInterval = 8;

      // Genesis block
      //if (pindexLast == NULL)
      //  return nProofOfWorkLimit;

      if (pindexLast->nHeight+1 < 135)
          return nProofOfWorkLimit;

      // Only change once per interval
      if ((pindexLast->nHeight+1) % nInterval != 0)
      {
          return pindexLast->nBits;
      }

      // 51% mitigation, courtesy of Art Forz
      int blockstogoback = nInterval-1;
      if ((pindexLast->nHeight+1) != nInterval)
          blockstogoback = nInterval;

      // Go back by what we want to be 14 days worth of blocks
      const CBlockIndex* pindexFirst = pindexLast;
      for (int i = 0; pindexFirst && i < blockstogoback; i++)
          pindexFirst = pindexFirst->pprev;
      assert(pindexFirst);

      // Limit adjustment step
      int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
      LogPrintf("  nActualTimespan = %d  before bounds\n", nActualTimespan);
          
           int64_t nActualTimespanMax = ((nTargetTimespan*75)/50);
           int64_t nActualTimespanMin = ((nTargetTimespan*50)/75);
          
      if (nActualTimespan < nActualTimespanMin)
          nActualTimespan = nActualTimespanMin;
      if (nActualTimespan > nActualTimespanMax)
          nActualTimespan = nActualTimespanMax;
                  
      // Retarget
      arith_uint256 bnNew;
      arith_uint256 bnBefore;
      bnNew.SetCompact(pindexLast->nBits);
      bnBefore=bnNew;
      bnNew *= nActualTimespan;
      bnNew /= nTargetTimespan;


      if (bnNew > UintToArith256(params.powLimit))
          bnNew = UintToArith256(params.powLimit);

      // debug print
      LogPrintf("GetNextWorkRequired_Original: nTargetTimespan = %d    nActualTimespan = %d\n", nTargetTimespan, nActualTimespan);
      LogPrintf("GetNextWorkRequired_Original: Before: %08x  %s\n", pindexLast->nBits, ArithToUint256(bnBefore).ToString());
      LogPrintf("GetNextWorkRequired_Original: After:  %08x  %s\n", bnNew.GetCompact(), ArithToUint256(bnNew).ToString());

      return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired_KGW(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, int algo)
{
          const int64_t BlocksTargetSpacing = 5 * 60; // 1 Minute
          unsigned int TimeDaySeconds = 60 * 60 * 24;
          int64_t PastSecondsMin = TimeDaySeconds * 0.5;
          int64_t PastSecondsMax = TimeDaySeconds * 14;
          uint64_t PastBlocksMin = PastSecondsMin / BlocksTargetSpacing;
          uint64_t PastBlocksMax = PastSecondsMax / BlocksTargetSpacing;

          /* current difficulty formula, megacoin - kimoto gravity well */
          const CBlockIndex *BlockLastSolved = pindexLast;
          const CBlockIndex *BlockReading = pindexLast;
          const CBlockHeader *BlockCreating = pblock;

          BlockCreating = BlockCreating;

          uint64_t PastBlocksMass = 0;
          int64_t PastRateActualSeconds = 0;
          int64_t PastRateTargetSeconds = 0;
          double PastRateAdjustmentRatio = double(1);
          arith_uint256 PastDifficultyAverage;
          arith_uint256 PastDifficultyAveragePrev;
          //CBigNum PastDifficultyAverage;
          //CBigNum PastDifficultyAveragePrev;
          double EventHorizonDeviation;
          double EventHorizonDeviationFast;
          double EventHorizonDeviationSlow;

      if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (unsigned int)BlockLastSolved->nHeight < PastBlocksMin) { return InitialDifficulty(params, algo); }

          for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
                  if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
                  PastBlocksMass++;

                  // We still use CBigNum here, because conversion to arith_uint256 fails to obtain the correct PastDifficultyAverage.
                  //if (i == 1) { PastDifficultyAverage = CBigNum().SetCompact(BlockReading->nBits); }
                  //else { PastDifficultyAverage = ((CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev; }

                  PastDifficultyAverage.SetCompact(BlockReading->nBits);
                  if (i > 1) {
                      // handle negative arith_uint256
                      if(PastDifficultyAverage >= PastDifficultyAveragePrev)
                          PastDifficultyAverage = ((PastDifficultyAverage - PastDifficultyAveragePrev) / i) + PastDifficultyAveragePrev;
                      else
                          PastDifficultyAverage = PastDifficultyAveragePrev - ((PastDifficultyAveragePrev - PastDifficultyAverage) / i);
                      }
                  PastDifficultyAveragePrev = PastDifficultyAverage;

                  PastRateActualSeconds = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
                  PastRateTargetSeconds = BlocksTargetSpacing * PastBlocksMass;
                  PastRateAdjustmentRatio = double(1);
                  if (PastRateActualSeconds < 0) { PastRateActualSeconds = 0; }
                  if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
                    PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);
                  }
                  EventHorizonDeviation = 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
                  EventHorizonDeviationFast = EventHorizonDeviation;
                  EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

                  if (PastBlocksMass >= PastBlocksMin) {
                          if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast)) { assert(BlockReading); break; }
                  }
                  if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
                  BlockReading = BlockReading->pprev;
          }

          arith_uint256 bnNew(PastDifficultyAverage);
          //LogPrintf("KGW %s  %08x  %s\n" , PastDifficultyAverage.getuint256().ToString().c_str(), bnNew.GetCompact(), ArithToUint256(bnNew).ToString());

          if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0) {
                  bnNew *= PastRateActualSeconds;
                  bnNew /= PastRateTargetSeconds;
          }


      if (bnNew > UintToArith256(params.powLimit))
          bnNew = UintToArith256(params.powLimit);

      /// debug print
      LogPrintf("KGW %g  %08x  %08x  %s\n" , PastRateAdjustmentRatio, BlockLastSolved->nBits, bnNew.GetCompact(), ArithToUint256(bnNew).ToString());

      return bnNew.GetCompact();
}

unsigned int GetNextWorkRequiredMULTI(const CBlockIndex* pindexLast, const Consensus::Params& params, int algo)
{
	unsigned int nProofOfWorkLimit = InitialDifficulty(params, algo);
	arith_uint256 bnNew;

	/* These checks and PoW limits are needed for the short transition to multi-algo, where we raised the limits, */
	/* and later restored to the current values. */
	if ((pindexLast->nHeight+1 == 225001) || (pindexLast->nHeight+1 == 225012) || (pindexLast->nHeight+1 == 225018) ||
	    (pindexLast->nHeight+1 == 225024) || (pindexLast->nHeight+1 == 225030) || (pindexLast->nHeight+1 == 225036) ||
	    (pindexLast->nHeight+1 == 225042))
	    {
	    /* skein and groestl */
	    bnNew = ~arith_uint256(0) >> 23;
	    LogPrintf("MULTI Use default POW Limit %08x for algo %s\n", bnNew.GetCompact(), GetAlgoName(algo));
	    return bnNew.GetCompact();
	    }
	if ((pindexLast->nHeight+1 == 225095))
	    {
	    /* qubit */
	    bnNew = ~arith_uint256(0) >> 22;
	    LogPrintf("MULTI Use default POW Limit %08x for algo %s\n", bnNew.GetCompact(), GetAlgoName(algo));
	    return bnNew.GetCompact();
	    }
	if ((pindexLast->nHeight+1 == 225237))
	    {
	    /* sha256d */
	    bnNew = ~arith_uint256(0) >> 32;
	    LogPrintf("MULTI Use default POW Limit %08x for algo %s\n", bnNew.GetCompact(), GetAlgoName(algo));
	    return bnNew.GetCompact();
	    }
	LogPrintf("MULTI GetNextWorkRequired RETARGET\n");
	LogPrintf("Algo: %s\n", GetAlgoName(algo));
	LogPrintf("Height (Before): %s\n", pindexLast->nHeight);

	// find first block in averaging interval
	// Go back by what we want to be nAveragingInterval blocks per algo
	const CBlockIndex* pindexFirst = pindexLast;
	for (int i = 0; pindexFirst && i < NUM_ALGOS*params.nAveragingInterval; i++)
	{
		pindexFirst = pindexFirst->pprev;
	}

	const CBlockIndex* pindexPrevAlgo = GetLastBlockIndexForAlgo(pindexLast, params, algo); // FIXME: bug hier.
	if (pindexPrevAlgo == nullptr || pindexFirst == nullptr)
	{
		LogPrintf("Use default POW Limit %08x for algo %s\n", nProofOfWorkLimit, GetAlgoName(algo));
		return nProofOfWorkLimit;
	}

	// Limit adjustment step
	// Use medians to prevent time-warp attacks
	int64_t nActualTimespan = pindexLast-> GetMedianTimePast() - pindexFirst->GetMedianTimePast();
	nActualTimespan = params.nAveragingTargetTimespan + (nActualTimespan - params.nAveragingTargetTimespan)/4;

	LogPrintf("nActualTimespan = %d before bounds\n", nActualTimespan);

	if (nActualTimespan < params.nMinActualTimespanV4)
		nActualTimespan = params.nMinActualTimespanV4;
	if (nActualTimespan > params.nMaxActualTimespanV4)
		nActualTimespan = params.nMaxActualTimespanV4;

	//Global retarget
	bnNew.SetCompact(pindexPrevAlgo->nBits);

	bnNew *= nActualTimespan;
	bnNew /= params.nAveragingTargetTimespan;

	//Per-algo retarget
	int nAdjustments = pindexPrevAlgo->nHeight + NUM_ALGOS - 1 - pindexLast->nHeight;
	if (nAdjustments > 0)
	{
		for (int i = 0; i < nAdjustments; i++)
		{
			bnNew *= 100;
			bnNew /= (100 + params.nLocalTargetAdjustment);
		}
	}
	else if (nAdjustments < 0)//make it easier
	{
		for (int i = 0; i < -nAdjustments; i++)
		{
			bnNew *= (100 + params.nLocalTargetAdjustment);
			bnNew /= 100;
		}
	}

        if (bnNew > UintToArith256(params.powLimit))
              bnNew = UintToArith256(params.powLimit);

        LogPrintf("MULTI %d  %d  %08x  %08x  %s\n", params.multiAlgoTimespan, nActualTimespan, pindexLast->nBits, bnNew.GetCompact(), ArithToUint256(bnNew).ToString());

	return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, int algo)
{
    // Genesis block
    if (pindexLast == nullptr)
        return InitialDifficulty(params, algo);

    if (params.fPowAllowMinDifficultyBlocks)
    {
        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2 minutes
        // then allow mining of a min-difficulty block.
        if (pblock->nTime > pindexLast->nTime + params.nTargetSpacing*2)
            return PowLimit(params);
    }


    if (pindexLast->nHeight+1 <= 5400) {
        return GetNextWorkRequired_Original(pindexLast, params, algo);
    } else if (pindexLast->nHeight + 1 <= 225000) {
        return GetNextWorkRequired_KGW(pindexLast, pblock,  params, algo);
    } else {
        return GetNextWorkRequiredMULTI(pindexLast, params, algo);
    }
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
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
            pindex->nTime > pindex->pprev->nTime + params.nTargetSpacing*2)
        {
            continue;
        }
        return pindex;
    }
    return nullptr;
}

uint256 GetPoWAlgoHash(const CBlockHeader& block)
{
    return block.GetPoWAlgoHash(Params().GetConsensus());
}
