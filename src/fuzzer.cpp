//
// Code for "fuzzing" transactions, to test implementations' network protocol handling
//

#include "util.h"
#include "serialize.h"
#include "main.h"
#include "wallet.h"
#include "net.h"
#include "fuzzer.h"

void
FuzzTransaction(const CTransaction& tx, const uint32_t& fuzzSeed, CDataStream& fuzzedDataRet)
{
    CTransaction tweaked = tx;
    tweaked.vin[0].scriptSig = (CScript() << OP_1) + tweaked.vin[0].scriptSig;

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

    // Instead of randomness, I hash the fuzzSeed counter
    // to get reproducible-when-needed fuzzing.
    //
    // Hashes for the unfuzzed and fuzzed transaction
    // are printed to debug.log; if you need to reproduce
    // a crash get the unfuzzed hash and fuzzseed values
    // from debug.log and then use the RPC 'relayfuzzed'
    // command to re-relay.
    //
    static uint64_t fuzzSeed = 0;

    if (fuzzSeed == 0)
        fuzzSeed = GetArg("-fuzzseed", GetTime());
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
