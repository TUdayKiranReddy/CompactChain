# CompactChain:An Efficient Stateless Chain for UTXO-model Blockchain
In this work, we propose a stateless blockchain called CompactChain, which compacts the entire state of the UTXO (Unspent Transaction Output) based blockchain systems into two RSA accumulators. The first accumulator is called Transaction Output (TXO) commitment which represents the TXO set. The second one is called Spent Transaction Output (STXO) commitment which represents the STXO set. In this work, we discuss three algorithms - (i) To update the TXO and STXO commitments by the miner. The miner also provides the proofs for the correctness of the updated commitments; (ii) To prove the transaction's validity by providing a membership witness in TXO commitment and non-membership witness against STXO commitment for a coin being spent by a user; (iii) To update the witness for the coin that is not yet spent; The experimental results evaluate the performance of the CompactChain in terms of time taken by a miner to update the commitments and time taken by a validator to verify the commitments and validate the transactions. We compare the performance of CompactChain with the existing state-of-art works on stateless blockchains. CompactChain shows a reduction in commitments update complexity and transaction witness size without compromising the system throughput (Transactions per second (TPS)).

Please cite our work if you find our repo useful in your work :)
```
@misc{reddy-reddy-arxiv22,
  doi = {10.48550/ARXIV.2211.06735},
  author = {Reddy, B Swaroopa and Reddy, T Uday Kiran},
  title = {CompactChain:An Efficient Stateless Chain for UTXO-model Blockchain},
  publisher = {arXiv},
  year = {2022}
}
```

## Installation
* Install FLINT 2.5.2
1. Download Flint 2.5.2 from https://www.flintlib.org/flint-2.5.2.tar.gz
2. Untar and navigate to the directory
2. Remove '-Wl' in 62 line of Makefile.subdirs
3. Configure and make library
```
    ./configure --prefix=/usr
    make
    make test
    make install
```
 * Install CRYPTO++
    `sudo apt-get install libcrypto++-dev`

## Running tests
* Build the executables
    `make`
* First generate randomBigInts using the executable in test/
* Navigate to test/ directory and execute TEST
    `./{}.out`

|         TEST         	|                                                Description                                               	|
|:--------------------:	|:--------------------------------------------------------------------------------------------------------:	|
|       textcctco      	|                                       CompactChain Tx Verification                                       	|
|    generate_random   	| Generate random keys for RSA and hashes for SHA256<br>Usage: ./generate_random.out {rsa/sha} {#Elements} 	|
|       testAccUp      	|                        Performs Accumulator update for both CompactChain and Boneh                       	|
|     textbonehTXO     	|                                          Boneh's Tx Verification                                         	|
|       textmctco      	|                                         MiniChain Tx Verification                                        	|
|      testMerkle      	|                                    Testing Merkle tree implementation                                    	|
|      testMMRTree     	|                                      Testing MMR tree implementation                                     	|
|     testproposed     	|                      Performs Accumulator update and verification for CompactChain                       	|
|     updatetxproof    	|                           Tx proof updating in both CompactChain and MiniChain                           	|
|       testWitUp      	|                     Comparision of Witness update for CompactChain, MiniChain, Boneh                     	|
| update_witness_boneh 	|                                         Witness update for Boneh                                         	|

## More tests
* Check `Memory_stats/RAM&Disk.ipynb` notebook for obtaining RAM and Disk usage on real time Bitcoin data.
* Check `Propagation\ delay/` library for simulating real time delays in blockchain network.

## References
* https://github.com/etremel/crypto-accumulators
