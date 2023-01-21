#ifndef RSAACCUMULATOR_H
#define RSAACCUMULATOR_H

#include <vector>

#include <flint/BigInt.hpp>
#include <flint/BigMod.hpp>

#include <openssl/crypto.h>
#include <openssl/rsa.h>

#include <algorithms/PrimeRepGenerator.hpp>
#include <algorithms/RSAKey.hpp>

#include <utils/ThreadPool.hpp>

namespace RSAAccumulator {

/**
 * Generates a public/private key pair for an RSA accumulator, given either
 * the size of each element that will be accumulated in bits (the elements
 * are assumed to all be a fixed size) or the size of the desired modulus in
 * bits (this must be at least 3 times the size of an element). If the
 * elementBits argument is 0 it will be ignored in favor of modulusBits, and
 * vice versa. The generated key is placed in the provided RSAKey object.
 *
 * @param elementBits (optional) the number of bits in an element that will
 *         be accumulated with this key pair. Ignored if 0.
 * @param modulusBits (optional) the number of bits in the RSA modulus that
 *         will be generated. Ignored if 0.
 * @param key the RSAKey object in which the generated key pair will be
 *         placed.
 */
void genKey(const unsigned int elementBits, const unsigned int modulusBits, RSAKey& key);

/**
 * Generates prime representatives for the given set of bigints, using the
 * given prime representative generator, and places the results in the
 * provided vector of bigints. Other accumulator methods that expect prime
 * representatives should use the result of this function.
 *
 * @param set a set of element values that will be used in an accumulator
 * @param repGen an implementation of PrimeRepGenerator that will be used
 *        to generate prime representatives for these elements
 * @param reps a set of prime numbers representing the element values, such
 *        that reps[i] is the representative for set[i] according to repGen
 * @param threadPool the ThreadPool to use for concurrent computation.
 */
void genRepresentatives(const std::vector<flint::BigInt>& set, PrimeRepGenerator& repGen,
                        std::vector<flint::BigInt>& reps, ThreadPool& threadPool);

// Private accumulator
void accumulateSetPvt(const std::vector<flint::BigInt>& reps, const RSAKey& key, flint::BigMod& accumulator);

/**
 * Accumulates the given set of prime representatives (stored as bigints)
 * using the given RSA accumulator key pair, placing the result into the
 * given BigMod. The BigMod's modulus will be set to the RSA modulus
 * contained in the public key.
 *
 * @param reps a vector of prime representatives of elements
 * @param key the key object for this RSA accumulator
 * @param accumulator A BigMod that will contain the accumulated
 *         value of the set after running this function
 * @param threadPool the ThreadPool to use for concurrent computation.
 */
void accumulateSet(const std::vector<flint::BigInt>& reps, const RSAKey& key,
                   flint::BigMod& accumulator, ThreadPool& threadPool);


void batchAdd(const std::vector<flint::BigInt> representatives, const RSAKey& rsaKey, flint::BigMod& prev_acc, flint::BigMod& accumulator, flint::BigMod& Q);
                       
void NIPoE_Prove(PrimeRepGenerator& repGen, const flint::BigMod& u, const flint::BigInt& x, const flint::BigMod& w, flint::BigMod& Q);

void NIPoE_Verify(const RSAKey& rsaKey, const std::vector<flint::BigInt>& representatives,
                            PrimeRepGenerator& repGen, flint::BigMod& u, const flint::BigMod& w, flint::BigMod& Q, bool& b);

void accumulateSet(const std::vector<flint::BigInt>& reps, const RSAKey::PublicKey& publicKey, flint::BigMod& accumulator, flint::BigInt& product, ThreadPool& threadPool);

void accumulateSet(const std::vector<flint::BigInt>& reps, const RSAKey::PublicKey& publicKey, flint::BigMod& accumulator, flint::BigInt& product);

void batchAdd(const std::vector<flint::BigInt>& set, const RSAKey& rsaKey,
                       ThreadPool& threadPool, const flint::BigMod& prev_acc, flint::BigMod& accumulator, flint::BigMod& Q);
                       
// void NIPoE_Prove(PrimeRepGenerator& repGen, flint::BigMod& u, const flint::BigInt& x, const flint::BigMod& w, flint::BigMod& Q);

// void NIPoE_Verify(const std::vector<flint::BigInt>& set, ThreadPool& threadPool, const RSAKey& rsaKey, 
//                             PrimeRepGenerator& repGen, flint::BigMod& u, const flint::BigMod& w, flint::BigMod& Q, bool& b);

void CreateNonMemWit(const flint::BigInt& x_k, const std::vector<flint::BigInt>& reps, const RSAKey& rsakey, const flint::BigMod& accumulator, flint::BigMod& d, flint::BigInt& b);
// void VerifyNonMemWit(const flint::BigInt& x_k, const std::vector<flint::BigInt>& reps, const RSAKey& rsakey, const flint::BigMod& accumulator_h, const flint::BigMod& accumulator_k, const flint::BigMod& d, const flint::BigInt& b, bool& ans);
void VerifyNonMemWit(const flint::BigInt& x_k, const RSAKey& rsakey, const flint::BigMod& accumulator_h, const flint::BigMod& accumulator_k, const flint::BigMod& d, const flint::BigInt& b, bool& ans);

//void UpdateNonMemWit(const flint::BigInt& x_k, const std::vector<flint::BigInt>& reps, const RSAKey& rsakey, const flint::BigMod& accumulator, flint::BigMod& d, flint::BigInt& b);
//void UpdateNonMemWit(const flint::BigInt& x_k, const std::vector<flint::BigInt>& elements, const RSAKey& rsakey, const flint::BigMod& accumulator, ThreadPool& threadPool, flint::BigMod& d, flint::BigInt& b);
void UpNonMemWit(const flint::BigInt& x_k, const flint::BigMod& d, const flint::BigInt& b, const std::vector<flint::BigInt>& reps, 
                const RSAKey& rsakey, const flint::BigMod& prev_acc, flint::BigMod& new_d, flint::BigInt& new_b);
/**
 * Computes a witness for each prime representative in the given set
 * (with respect to the entire set), using the given RSA accumulator key
 * pair. Places the resulting witnesses in the given vector, preserving
 * order such that witnesses[i] is a witness for reps[i]. Note that
 * witnesses is expected to be initialized to the same size as reps; this
 * method does not create any new multi_bigmod objects.
 *
 * @param reps A vector of prime representatives of elements
 * @param key The key object for this RSA accumulator
 * @param witnesses A vector of BigMod that will contain the witnesses after
 *        running this function
 * @param threadPool the ThreadPool to use for concurrent computation.
 */
void witnessesForSet(const std::vector<flint::BigInt>& reps, const RSAKey& key,
                     std::vector<flint::BigMod>& witnesses, ThreadPool& threadPool);

/**
 * Computes a witness for each prime representative in the given set (with
 * respect to the entire set), using the given RSA accumulator public key.
 *
 * @param reps A vector of prime representatives of elements
 * @param publicKey The public key for this RSA accumulator
 * @param witnesses A vector of BigMod that will contain the witnesses after
 *        running this function
 * @param threadPool the ThreadPool to use for concurrent computation.
 */
void witnessesForSet(const std::vector<flint::BigInt>& reps, const RSAKey::PublicKey& publicKey,
                     std::vector<flint::BigMod>& witnesses, ThreadPool& threadPool);

void UpMemWit(const std::vector<flint::BigInt>& set, const RSAKey& rsaKey, ThreadPool& threadPool, 
                    flint::BigMod& prev_wit);
/**
 * Verifies the given element as a member of the set represented by the
 * given accumulator, by using the given witness and public key. Note that
 * this requires re-generating the prime representative for the element,
 * since the client cannot trust the representatives provided by the server
 * to be correct.
 *
 * @param element a bigint that may have been previously accumulated with
 *         {@code accumulator}
 * @param witness a multi_bigmod that is a witness for {@code element}'s
 *         membership in the set (i.e. the accumulation of all elements of
 *         the set except for {@code element}).
 * @param accumulator a multi_bigmod containing the accumulated value of
 *         the set that {@code element} should be a member of
 * @param pubKey the public key for the accumulator
 * @return true if the witness verifies the element's set membership with
 *          the accumulator, false otherwise
 */
void verify(const flint::BigInt& element, const flint::BigMod& witness, const flint::BigMod& accumulator,
            const RSAKey::PublicKey& pubKey, bool& b);

//void Verify(const std::vector<flint::BigInt>& set, const std::vector<flint::BigMod>& witnesses, const flint::BigMod& accumulator, 
//              const RSAKey::PublicKey& publicKey, ThreadPool& threadPool, std::vector<bool>& b);

void batch_delete_using_membership_proofs(const flint::BigMod& A_pre_delete, const std::vector<flint::BigInt>& x_list, const std::vector<flint::BigMod>& proofs_list, const RSAKey::PublicKey& publicKey,
                                              PrimeRepGenerator& repGen, flint::BigMod& A_post_delete, flint::BigInt& product, flint::BigMod& proof, ThreadPool& threadPool);

void witness_update_boneh(const flint::BigMod& A_post_delete, const flint::BigMod& prev_wit, const std::vector<flint::BigInt>& x_lists, 
                    const std::vector<flint::BigInt>& y_lists, const flint::BigInt& x_k, const RSAKey& rsakey, flint::BigMod& wit_post_delete,flint::BigMod& wit_final, ThreadPool& threadPool);

};  // namespace RSAAccumulator

#endif  // RSAACCUMULATOR_H