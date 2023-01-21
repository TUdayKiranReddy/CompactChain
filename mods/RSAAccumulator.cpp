/*
 * Edward Tremel - etremel@cs.brown.edu
 * March 2013
 */

#include <algorithm>
#include <functional>
#include <thread>
#include <vector>

#include <utils/LibConversions.hpp>
#include <utils/Pointers.hpp>
#include <utils/ThreadPool.hpp>

#include <algorithms/OraclePrimeRep.hpp>
#include <algorithms/PrimeRepGenerator.hpp>
#include <algorithms/RSAAccumulator.hpp>

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
//#include <algorithms/RSAKey.hpp>


using std::future;
using std::vector;

namespace RSAAccumulator {

/*-------------------------------Key Generation-------------------------------*/

void genKey(const unsigned int elementBits, const unsigned int modulusBits, RSAKey& key) {
    unsigned int modBits;
    if(modulusBits == 0) {
        modBits = 3 * elementBits + 1;
    } else if(elementBits == 0) {
        modBits = modulusBits;
    } else {
        modBits = std::max(3 * elementBits + 1, modulusBits);
    }
    //Use Crypto++ to generate an RSA modulus
    CryptoPP::AutoSeededRandomPool random;
    CryptoPP::RSA::PrivateKey rsaKey;
    rsaKey.GenerateRandomWithKeySize(random, modBits);
    LibConversions::CryptoPPToFlint(rsaKey.GetModulus(), key.getPublicKey().rsaModulus);
    LibConversions::CryptoPPToFlint(rsaKey.GetPrime1(), key.getSecretKey().p);
    LibConversions::CryptoPPToFlint(rsaKey.GetPrime2(), key.getSecretKey().q);
    //Apparently, this is a reasonable number to hard-code for the base
    //flint:: BigInt N = 65537
    key.getPublicKey().base = flint::BigMod(key.getPublicKey().rsaModulus/2 - 1, key.getPublicKey().rsaModulus);
    //For now, just hard-code in which PrimeRepGenerator to instantiate...
    key.getPublicKey().primeRepGenerator = std::make_unique<OraclePrimeRep>();
}

/*-------------------------------Representatives------------------------------*/

void genRepresentatives(const vector<flint::BigInt>& set, PrimeRepGenerator& repGen,
                        vector<flint::BigInt>& reps, ThreadPool& threadPool) {
    vector<future<void>> futures;
    for(vector<flint::BigMod>::size_type element = 0; element < set.size(); element++) {
        //Submit repGen.genRepresentative(set[element], reps[element]) to the thread pool
        futures.push_back(threadPool.enqueue<void>([&, element]() {
            repGen.genRepresentative(set.at(element), reps.at(element));
        }));
    }
    for(auto& future : futures) {
        future.get();
    }
}

/*--------------------------Private key accumulation--------------------------*/

void accumulateSet(const vector<flint::BigInt>& reps, const RSAKey& key, flint::BigMod& accumulator,
                   ThreadPool& threadPool) {
    flint::BigInt phiOfN = (key.getSecretKey().p - 1) * (key.getSecretKey().q - 1);
    //The accumulator's exponent is the product of all the representatives mod phi(N)
    flint::BigMod exponent(1, phiOfN);
    for(auto rep : reps) {
        exponent *= rep;
    }
    //Don't trust the caller to have initialized accumulator's modulus
    accumulator.setModulus(key.getPublicKey().rsaModulus);
    flint::power(key.getPublicKey().base, exponent.getMantissa(), accumulator);
}

/*---------------------------Public key accumulation--------------------------*/
/**
 * Private (not in header) helper method that accumulates some or all of a set
 * using only the public key. If a valid indexToSkip is provided, it will
 * accumulate only the elements excluding that index. If indexToSkip is >= reps.size(),
 * it will accumulate the entire set.
 * @param reps The set of representatives of elements to accumulate
 * @param indexToSkip The index of the set indicating the element not to accumulate
 * @param publicKey The public key for the RSA accumulator
 * @return A BigMod that containing the result of accumulation; this
 *        could be an accumulator, if the entire set is accumulated, or a
 *        witness, if an element is skipped.
 */
flint::BigInt accumulateSetHelper(const vector<flint::BigInt>& reps, const size_t indexToSkip,
                                  const RSAKey::PublicKey& publicKey) {
    //flint::BigMod output;
    flint::BigInt product = 1;
    //Ensure the modulus is set correctly
    //output.setModulus(publicKey.rsaModulus);
    //output = publicKey.base;
    //Safely allow the client to set an invalid skip index
    size_t end = std::min(indexToSkip, reps.size());
    //Split the loop into two parts, before and after the skip index
    for(size_t i = 0; i < end; i++) {
       // output ^= reps.at(i);
        product *= reps.at(i);
    }
    for(size_t i = indexToSkip + 1; i < reps.size(); i++) {
       // output ^= reps.at(i);
        product *= reps.at(i);
    }
    //output ^= product;
    //Unfortunately there's no way to parallelize this, because each exponentiation
    //depends on the previous result, and without phi(N) we can't combine exponents
    //return output;
    return product;
}

flint::BigMod witnessHelper(const vector<flint::BigInt>& reps, const size_t indexToSkip,
                                  const RSAKey::PublicKey& publicKey) {
    flint::BigMod output;
    flint::BigInt product = 1;
    //Ensure the modulus is set correctly
    output.setModulus(publicKey.rsaModulus);
    output = publicKey.base;
    //Safely allow the client to set an invalid skip index
    size_t end = std::min(indexToSkip, reps.size());
    //Split the loop into two parts, before and after the skip index
    for(size_t i = 0; i < end; i++) {
        product *= reps.at(i);
      //  output ^= reps.at(i);
    }
    for(size_t i = indexToSkip + 1; i < reps.size(); i++) {
        product *= reps.at(i);
       // output ^= reps.at(i);
    }
    //Unfortunately there's no way to parallelize this, because each exponentiation
    //depends on the previous result, and without phi(N) we can't combine exponents
    return output^product;
}

void accumulateSet(const vector<flint::BigInt>& reps, const RSAKey::PublicKey& publicKey, flint::BigMod& accumulator, flint::BigInt& product) {
    //Just wrap the helper, hiding the "indexToSkip" parameter
    accumulator = witnessHelper(reps, reps.size(), publicKey);
    //product = accumulateSetHelper(reps, reps.size(), publicKey);
    //accumulator.setModulus(publicKey.rsaModulus);
    //accumulator = publicKey.base;
    //accumulator ^= product;
}


/*---------------------------Batch Addition--------------------------*/
void batchAdd(const vector<flint::BigInt>& set, const RSAKey& rsaKey,
                       ThreadPool& threadPool, flint::BigMod& prev_acc, flint::BigMod& accumulator, flint::BigMod& Q) {
	std::vector<flint::BigInt> representatives(set.size());
    RSAAccumulator::genRepresentatives(set, *(rsaKey.getPublicKey().primeRepGenerator),
                                       representatives, threadPool);
    flint::BigInt product;				   
	product = accumulateSetHelper(representatives, representatives.size(), rsaKey.getPublicKey());
//	accumulator.setModulus(publicKey.rsaModulus);
    accumulator = prev_acc;
    accumulator ^= product;
//	std::cout << "Accumulator calculated: " << accumulator << std::endl;
	RSAAccumulator::NIPoE_Prove(*(rsaKey.getPublicKey().primeRepGenerator), prev_acc, product, accumulator, Q);
}

/*---------------------------NI-PoE Proof Generation--------------------------*/
void NIPoE_Prove(PrimeRepGenerator& repGen, const flint::BigMod& u, const flint::BigInt& x, const flint::BigMod& w, flint::BigMod& Q) {
	flint::BigInt l, q;
	std::string str;
	str = u.getMantissa().toString();
	str += x.toString();
	str += w.getMantissa().toString();
	
	ulong n = str.length();
	char c[n + 1];
	strcpy(c, str.c_str());
	repGen.genRepresentative(flint::BigInt(c, 10), l);
	q = x/l;

	Q = u;
	Q ^= q;
//	std::cout << "Q calculated" << std::endl;
}

///*---------------------------NI-PoE Proof Verification--------------------------*/
bool NIPoE_Verify(const vector<flint::BigInt>& set, ThreadPool& threadPool, const RSAKey& rsaKey,PrimeRepGenerator& repGen, 
							flint::BigMod& u, const flint::BigMod& w, flint::BigMod& Q) {
	std::vector<flint::BigInt> representatives(set.size());
    RSAAccumulator::genRepresentatives(set, *(rsaKey.getPublicKey().primeRepGenerator),
                                       representatives, threadPool);
    flint::BigInt product;				   
	product = accumulateSetHelper(representatives, representatives.size(), rsaKey.getPublicKey());
	
	flint::BigInt s = 0, l, r, q;
	std::string str;
	str = u.getMantissa().toString();
	str += product.toString();
	str += w.getMantissa().toString();
	
	ulong n = str.length();
	char c[n + 1];
	strcpy(c, str.c_str());
	
	repGen.genRepresentative(flint::BigInt(c, 10), l);
	q = product/l;
	q *= l;
	r = product - q;
	//std::cout << "r:" << r << "\n" ;
	flint::BigMod temp;
	temp = u;
	Q ^= l;
	temp ^= r;
	Q *= temp;
	return Q.equals(w);
}

/*-----------------------Private key witness generation-----------------------*/

//Compute products for the witness exponents left-to-right, saving each partial product
vector<flint::BigMod> multiplyLeftProducts(const vector<flint::BigInt>& reps, const flint::BigInt& phiOfN) {
    vector<flint::BigMod> leftProducts(reps.size() + 1, flint::BigMod(1, phiOfN));
    for(vector<flint::BigMod>::size_type i = 1; i <= reps.size(); i++) {
        leftProducts.at(i) = leftProducts.at(i - 1) * reps.at(i - 1);
    }
    return leftProducts;
}

//Compute products for the witness exponents right-to-left, saving each partial product
vector<flint::BigMod> multiplyRightProducts(const vector<flint::BigInt>& reps, const flint::BigInt& phiOfN) {
    vector<flint::BigMod> rightProducts(reps.size() + 1, flint::BigMod(1, phiOfN));
    for(vector<flint::BigMod>::size_type i = reps.size() - 1; i != (vector<flint::BigMod>::size_type) - 1; i--) {
        rightProducts.at(i) = rightProducts.at(i + 1) * reps.at(i);
    }
    return rightProducts;
}

//Holds onto the temporary exponent so it doesn't go out of scope, and resolves the ambiguous overload to power
void powerWrapper(const flint::BigMod base, const flint::BigMod& leftProduct,
                  const flint::BigMod& rightProduct, flint::BigMod& witness) {
    flint::BigMod exponent = leftProduct * rightProduct;
    flint::power(base, exponent.getMantissa(), witness);
}

void witnessesForSet(const vector<flint::BigInt>& reps, const RSAKey& key, vector<flint::BigMod>& witnesses,
                     ThreadPool& threadPool) {
    flint::BigInt phiOfN = (key.getSecretKey().p - 1) * (key.getSecretKey().q - 1);
    //Compute left and right products in threads.
    //The vectors will be initialized in the threads,
    //since initialization is O(n) and can be done in parallel
    future<vector<flint::BigMod>> leftFuture = threadPool.enqueue<vector<flint::BigMod>>([&]() {
        return multiplyLeftProducts(reps, phiOfN);
    });
    future<vector<flint::BigMod>> rightFuture = threadPool.enqueue<vector<flint::BigMod>>([&]() {
        return multiplyRightProducts(reps, phiOfN);
    });
    //Wait for both threads to finish
    vector<flint::BigMod> leftProducts = leftFuture.get();
    vector<flint::BigMod> rightProducts = rightFuture.get();
    //Generate exponent for element i's witness by multiplying left-product i with right-product i+1
    vector<future<void>> powerResults;
    for(vector<flint::BigMod>::size_type i = 0; i < reps.size(); i++) {
        witnesses.at(i).setModulus(key.getPublicKey().rsaModulus);
        powerResults.push_back(threadPool.enqueue<void>([&, i]() {
            powerWrapper(key.getPublicKey().base, leftProducts.at(i), rightProducts.at(i + 1), witnesses.at(i));
        }));
    }
    for(auto& future : powerResults) {
        future.get();
    }
}

/*------------------------Public key witness generation-----------------------*/

void witnessesForSet(const std::vector<flint::BigInt>& reps, const RSAKey::PublicKey& publicKey,
                     vector<flint::BigMod>& witnesses, ThreadPool& threadPool) {
    vector<std::future<flint::BigMod>> futures;
    //Submit a task for each witness
    for(size_t witnessIndex = 0; witnessIndex < reps.size(); witnessIndex++) {
        futures.push_back(threadPool.enqueue<flint::BigMod>(
                [&reps, &publicKey, witnessIndex]() {
                    return witnessHelper(reps, witnessIndex, publicKey);
                }));
    }
    //Wait for them all to finish
    for(size_t witnessIndex = 0; witnessIndex < reps.size(); witnessIndex++) {
        witnesses.at(witnessIndex) = futures.at(witnessIndex).get();
    }
}

void UpMemWit(const vector<flint::BigInt>& set, const RSAKey& rsaKey, ThreadPool& threadPool, flint::BigMod& prev_wit) {
	std::vector<flint::BigInt> representatives(set.size());
    RSAAccumulator::genRepresentatives(set, *(rsaKey.getPublicKey().primeRepGenerator),
                                       representatives, threadPool);
    flint::BigInt product;				   
	product = accumulateSetHelper(representatives, set.size(), rsaKey.getPublicKey());
    
    prev_wit ^= product;
}

/*--------------------------------Verification--------------------------------*/

bool verify(const flint::BigInt& element, const flint::BigMod& witness, const flint::BigMod& accumulator, const RSAKey::PublicKey& pubKey) {
    if(witness.getModulus() != pubKey.rsaModulus || accumulator.getModulus() != pubKey.rsaModulus) {
        std::cout << "Verification failed due to modulus mismatch. Witness modulus was ";
        std::cout << witness.getModulus() << std::endl;
        std::cout << "Accumulator modulus was: " << accumulator.getModulus();
        std::cout << ". Public Key modulus was: " << pubKey.rsaModulus << std::endl;
        return false;
    }
    flint::BigInt elementRep;
    pubKey.primeRepGenerator->genRepresentative(element, elementRep);
    flint::BigMod accCandidate(pubKey.rsaModulus);
    flint::power(witness, elementRep, accCandidate);
    bool valid = accCandidate == accumulator;
    if(!valid) {
        std::cout << "Verification failed! Representative for element " << element << " was " << elementRep << std::endl;
    }
    return valid;
}

//void Verify(const std::vector<flint::BigInt>& set, const std::vector<flint::BigMod>& witnesses, const flint::BigMod& accumulator, 
				//const RSAKey::PublicKey& publicKey, ThreadPool& threadPool, std::vector<bool>& b) {
    //vector<std::future<flint::BigMod>> futures;
    //vector<flint::BigMod> accCandidate;
    //for(size_t i = 0; i < set.size(); i++) {
				////accCandidate.at(i) = 0;
				//accCandidate.at(i) = (publicKey.rsaModulus);
				//futures.push_back(threadPool.enqueue<flint::BigMod>(
                //[&, i]() {
                    //return flint::power(witnesses.at(i), set.at(i), accCandidate.at(i));
                //}));
		//}
	////Wait for them all to finish
	////std::vector<bool> b;
    //for(size_t i = 0; i < set.size(); i++) {
        //b.at(i) = (futures.at(i).get() == accumulator);
    //}
//}

}  // namespace RSAAccumulator
