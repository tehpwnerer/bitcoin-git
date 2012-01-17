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
    toInsert = OpCodes(rgen, nToInsert);

    scriptSig.insert(scriptSig.begin(), toInsert.begin(), toInsert.end());
}

// Change one bit in s:
void
ToggleBit(RGen& rgen, CDataStream& s)
{
    int byte = R(rgen, s.size());
    unsigned char mask = 1 << R(rgen, 8);
    s[byte] = s[byte]^mask;
}

// Change one byte in s:
void
ChangeByte(RGen& rgen, CDataStream& s)
{
    int byte = R(rgen, s.size());
    unsigned char bits = 1+R(rgen, 255); // 1-255
    s[byte] = s[byte]^bits;
}

// Insert n random bytes into s, at a random location:
void
InsertBytes(RGen& rgen, CDataStream& s, int n)
{
    CDataStream s2(Bytes(rgen, n));
    int where = R(rgen, s.size());
    s.insert(s.begin()+where, s2.begin(), s2.end());
}

// Erase n random bytes, at a random location:
void
EraseBytes(RGen& rgen, CDataStream& s, int n)
{
    if (n > s.size()) n = s.size();
    int where = R(rgen, s.size()-n);
    s.erase(s.begin()+where, s.begin()+where+n);
}

void
FuzzTransaction(const CTransaction& tx, const uint64_t& fuzzSeed, CDataStream& fuzzedDataRet)
{
    RGen rgen;
    rgen.seed(fuzzSeed);
    
    CTransaction tweaked = tx;
    TweakScriptSig(rgen, tweaked);

    // Mess with another input 10% of the time:
    if (R(rgen, 10) == 0)
        TweakScriptSig(rgen, tweaked);

    fuzzedDataRet << tweaked;

    // 10% chance of each of these:
    if (R(rgen, 10) == 0)
        ToggleBit(rgen, fuzzedDataRet);
    if (R(rgen, 10) == 0)
        ChangeByte(rgen, fuzzedDataRet);
    if (R(rgen, 10) == 0)
        InsertBytes(rgen, fuzzedDataRet, RExp(rgen, 500));
    if (R(rgen, 10) == 0)
        EraseBytes(rgen, fuzzedDataRet, R(rgen, fuzzedDataRet.size()));
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
