Hacked version of Bitcoin that "fuzzes" transactions before sending them.

Usage:

Just like normal bitcoin/bitcoind, but it randomly corrupts transactions before announcing them to the network.

So to use, compile and then use the sendtoaddress/sendmany/sendfrom RPC commands to generate transactions that will be fuzzed.

Use the -numfuzzed command-line switch (default 1) to set how many fuzzed transactions are generated for each send.

Types of "high-level" fuzzing done:

* Change the transaction ID by inserting an OP_1 at the front of the first scriptSig

TOOD:

Types of "low-level" fuzzing to be done:

* Change one or more bits in one of the transaction's bytes

* Delete one or more bytes

* Insert one or more random bytes

Types of "high-level" fuzzing to be done:

* Change the scriptPubKey an

