#ifndef ORACLEPRIMEREP_H
#define ORACLEPRIMEREP_H

#include <algorithms/PrimeRepGenerator.hpp>
#include <flint/BigInt.hpp>

/**
 * Prime representative generator that uses a secure hash function with salted
 * input as an "oracle" to produce a fixed-size version of an element, then adds
 * padding bits and finds the next highest prime from the oracle's output.
 */
class OraclePrimeRep : public PrimeRepGenerator {
public:
    OraclePrimeRep();
    ~OraclePrimeRep();

    void genRepresentative(const flint::BigInt& element, flint::BigInt& representative);

private:
    /**
     * The number of random bytes to append to the element before hashing it.
     */
    static const int SALT_BYTES = 2;
    /**
     * The number of bits to add to the lower-order end of the hash before
     * finding the next highest prime.
     */
    static const int PADDING_LENGTH = 8;
};

#endif  // ORACLEPRIMEREP_H
