//
// Code for "fuzzing" transactions, to test implementations' network protocol handling
//

#include <boost/random/exponential_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include "util.h"
#include "serialize.h"
#include "main.h"
#include "wallet.h"
#include "net.h"
#include "fuzzer.h"

using namespace boost::random;

typedef boost::random::mt19937 RGen; // Mersenne twister pseudo-random-number generator type

// Return integer from [0...n)
static int
R(RGen& rgen, int n)
{
    uniform_int_distribution<> d(0,n-1);
    return d(rgen);
}

// Return integer from [0..n),
// but with values near 0 exponentially more likely
static int
RExp(RGen& rgen, int n)
{
    exponential_distribution<> d(2.0);
    double v = d(rgen) * n / 5.0;

    if (v > n-1)
        return n-1;
    return int(v);
}

// Return n pseudo-random bytes
static std::vector<unsigned char>
Bytes(RGen& rgen, int n)
{
    std::vector<unsigned char> result;
    for (int i = 0; i < n; i++)
        result.push_back(static_cast<unsigned char>(R(rgen, 0x100)));
    return result;
}

// Return vector of n pretty-likely-to-be-valid Script opcodes:
static std::vector<unsigned char>
OpCodes(RGen& rgen, int n)
{
    std::vector<unsigned char> result;
    for (int i = 0; i < n; i++)
    {
        result.push_back(static_cast<unsigned char>(R(rgen, OP_NOP10+1)));
    }
    return result;
}


//
// Add random bytes to one of tx's scriptSig's.
// This will sometimes be harmless, just changing the
// transaction hash, and sometimes make the transaction
// invalid.
//
void
TweakScriptSig(RGen& rgen, CTransaction& tx)
{
    int whichTxIn = R(rgen, tx.vin.size());

    int nToInsert = RExp(rgen, 1000)+1;
    CScript& scriptSig = tx.vin[whichTxIn].scriptSig;
    std::vector<unsigned char> toInsert;
    if (R(rgen, 10) == 0)
        toInsert = Bytes(rgen, nToInsert); // Random bytes 10% of the time
    else
        toInsert = OpCodes(rgen, nToInsert); // Mostly-valid opcodes the rest of the time

    scriptSig.insert(scriptSig.begin(), toInsert.begin(), toInsert.end());
}

void
FuzzTransaction(const CTransaction& tx, const uint64_t& fuzzSeed, CDataStream& fuzzedDataRet)
{
    RGen rgen;
    rgen.seed(fuzzSeed);
    
    CTransaction tweaked = tx;
    TweakScriptSig(rgen, tweaked);

    if (R(rgen, 17) == 0)
        TweakScriptSig(rgen, tweaked);

    fuzzedDataRet << tweaked;
}

void
FuzzRelayTransaction(const CTransaction& tx)
{
    // No fuzzing on main net for now:
    if (!fTestNet)
    {
        printf("ERROR: fuzzing enabled only on testnet\n");
        return;
    }

    CDataStream ss(SER_NETWORK);

    static bool fInitialized = false;
    static uint64_t fuzzSeed = 0;

    if (!fInitialized)
    {
        fuzzSeed = GetArg("-fuzzseed", GetTime());
        fInitialized = true;
    }
    else
        ++fuzzSeed;

    FuzzTransaction(tx, fuzzSeed, ss);

    uint256 hash = Hash(ss.begin(), ss.end());

    printf("Relaying fuzzed tx %s\n", hash.ToString().c_str());
    printf(" (wallet tx: %s fuzzSeed: %u)\n", tx.GetHash().ToString().c_str(), fuzzSeed);

    if (fDebug)
    {
        printf("fuzzed hex:\n");
        PrintHex(ss.begin(), ss.end());
    }

    RelayMessage(CInv(MSG_TX, hash), ss);
}
