# CompactChain:An Efficient Stateless Chain for UTXO-model Blockchain
In this work, we propose a stateless blockchain called CompactChain, which compacts the entire state of the UTXO (Unspent Transaction Output) based blockchain systems into two RSA accumulators. The first accumulator is called Transaction Output (TXO) commitment which represents the TXO set. The second one is called Spent Transaction Output (STXO) commitment which represents the STXO set. In this work, we discuss three algorithms - (i) To update the TXO and STXO commitments by the miner. The miner also provides the proofs for the correctness of the updated commitments; (ii) To prove the transaction's validity by providing a membership witness in TXO commitment and non-membership witness against STXO commitment for a coin being spent by a user; (iii) To update the witness for the coin that is not yet spent; The experimental results evaluate the performance of the CompactChain in terms of time taken by a miner to update the commitments and time taken by a validator to verify the commitments and validate the transactions. We compare the performance of CompactChain with the existing state-of-art works on stateless blockchains. CompactChain shows a reduction in commitments update complexity and transaction witness size without compromising the system throughput (Transactions per second (TPS)).

## Installation
* Install FLINT 2.5.2
1. Download Flint 2.5.2 from https://www.flintlib.org/flint-2.5.2.tar.gz
2. Untar and navigate to the directory
2. Remove '-Wl' in 62 line of Makefile.subdirs
3. Configure and make library

    ./configure --prefix=/usr
    make
    make test
    make install

 * Install CRYPTO++

    sudo apt-get install libcrypto++-dev

## Running tests
* Build the executables

    make

* Navigate to test/ directory and execute TEST

    ./{}.out

