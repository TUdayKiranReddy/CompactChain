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

using std::future;
using std::vector;
#define THREAD_MAX 16

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

    void accumulateSetPvt(const vector<flint::BigInt>& reps, const RSAKey& key, flint::BigMod& accumulator) {
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
    // Creation of accumulator with Multi Threading
    void calculate_product(flint::BigInt& product, const vector<flint::BigInt>& reps, vector<flint::BigInt>::size_type i, vector<flint::BigInt>::size_type j){
    	for(vector<flint::BigInt>::size_type s=i; s<=j; s++){
    		product *= reps.at(s);
    	}
    }

    flint::BigInt accumulateSetHelper(const vector<flint::BigInt>& reps, const size_t indexToSkip, const RSAKey::PublicKey& publicKey, ThreadPool& threadpool) {
        vector<flint::BigInt> products(THREAD_MAX, 1);
        vector<flint::BigInt>::size_type start=0, end=0;
       
	std::thread t[THREAD_MAX];
        for(int j=0;j<THREAD_MAX;j++){
            start = (j*reps.size()/THREAD_MAX);
            end = ((j+1)*reps.size()/THREAD_MAX)-1;            
            t[j] =std::thread(calculate_product, std::ref(products[j]), std::ref(reps), start, end);
        }

        for(int j=0;j<THREAD_MAX;j++)
            t[j].join();
       
	flint::BigInt product=1;
       
       calculate_product(product, products, 0, THREAD_MAX-1);
        
       return product;
    }

    void accumulateSet(const vector<flint::BigInt>& reps, const RSAKey::PublicKey& publicKey, flint::BigMod& accumulator, flint::BigInt& product, ThreadPool& threadPool) {
        //Just wrap the helper, hiding the "indexToSkip" parameter
        //accumulator = accumulateSetHelper(reps, reps.size(), publicKey, product);
        product = accumulateSetHelper(reps, reps.size(), publicKey, threadPool);
        accumulator.setModulus(publicKey.rsaModulus);
        accumulator = publicKey.base;
        accumulator ^= product;
    }
    // 

    // Without multi threading
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
    void batchAdd ( const vector<flint::BigInt> representatives, const RSAKey& rsaKey, flint::BigMod& prev_acc, flint::BigMod& accumulator, flint::BigMod& Q) {
        // std::vector<flint::BigInt> representatives(set.size());
        // RSAAccumulator::genRepresentatives(set, *(rsaKey.getPublicKey().primeRepGenerator),
        //                                    representatives, threadPool);
        flint::BigInt product;                 
        product = accumulateSetHelper(representatives, representatives.size(), rsaKey.getPublicKey());
        accumulator = prev_acc;
        accumulator ^= product;

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
    }

    ///*---------------------------NI-PoE Proof Verification--------------------------*/
    void NIPoE_Verify(const RSAKey& rsaKey, const vector<flint::BigInt>& representatives, PrimeRepGenerator& repGen, 
                                flint::BigMod& u, const flint::BigMod& w, flint::BigMod& Q, bool& b) {
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
        
        Q ^= l;
        u ^= r;
        Q *= u;
        b = Q.equals(w);
    }

    flint::BigMod mul_inv(const flint::BigMod& b, const flint::BigInt& n){
        flint::BigInt g, x, y;
        fmpz_xgcd(g.value, x.value, y.value, b.value, n.value);
        flint::BigMod a(x.value, n);
        return a;
    }

    /*--------------Create Non-Membership Witness---------------------*/
    void CreateNonMemWit(const flint::BigInt& x_k, const vector<flint::BigInt>& reps, const RSAKey& rsakey, const flint::BigMod& accumulator, flint::BigMod& d, flint::BigInt& b){
        flint::BigInt product = 1;
        calculate_product(product, reps, 0, reps.size()-1);
            
        flint::BigInt a, x_k_rep;
        PrimeRepGenerator& repGen = *(rsakey.getPublicKey().primeRepGenerator); 
        RSAKey::PublicKey& publicKey = rsakey.getPublicKey();

        repGen.genRepresentative(x_k, x_k_rep); 
        flint::bezout_coefficients(x_k_rep, product, a, b);
        if(a < 0){
            flint::BigInt positive_a = flint::BigInt(-1)*a;
            flint::BigMod inverse_A0 = mul_inv(accumulator, publicKey.rsaModulus);
            flint::power(inverse_A0, positive_a, d);
        }
        else
            flint::power(accumulator, a, d);
    }

    /*------------Verify Non-Membership Witness-------------------*/
    void VerifyNonMemWit(const flint::BigInt& x_k, const RSAKey& rsakey, const flint::BigMod& accumulator_h, const flint::BigMod& accumulator_k, const flint::BigMod& d, const flint::BigInt& b, bool& ans){
        flint::BigInt x_k_rep;
        PrimeRepGenerator& repGen = *(rsakey.getPublicKey().primeRepGenerator);
        repGen.genRepresentative(x_k, x_k_rep);

        flint::BigMod fp, sp;
        if(b<0){
            flint::BigInt positive_b = flint::BigInt(-1)*b;
            flint::BigMod inverse_A = mul_inv(accumulator_h, rsakey.getPublicKey().rsaModulus);
            flint::power(inverse_A, positive_b, sp);
        }
        else
            flint::power(accumulator_h, b, sp);
        flint::power(d, x_k_rep, fp);
        ans =  (fp*sp == accumulator_k);
    }

    /*--------------Update Non-Membership Witness---------------------*/
    void UpNonMemWit(const flint::BigInt& x_k, const flint::BigMod& d, const flint::BigInt& b, const vector<flint::BigInt>& reps, 
                const RSAKey& rsakey, const flint::BigMod& prev_acc, flint::BigMod& new_d, flint::BigInt& new_b){
        
        flint::BigInt product = 1;
        product = accumulateSetHelper(reps, reps.size(), rsakey.getPublicKey());
            
        flint::BigInt a_0, b_0, r = b, x_k_rep;
        flint::BigMod A_0;
        
        PrimeRepGenerator& repGen = *(rsakey.getPublicKey().primeRepGenerator);
        repGen.genRepresentative(x_k, x_k_rep); 
        
        flint::bezout_coefficients(x_k_rep, product, a_0, b_0);
        new_b = b;
        new_b *= b_0;
 
        r *= a_0;
        
        if(r < 0){
            flint::BigInt positive_r = flint::BigInt(-1)*r;
            flint::BigMod inverse_A0 = mul_inv(prev_acc, rsakey.getPublicKey().rsaModulus);
            flint::power(inverse_A0, positive_r, A_0);
        }
        else
            flint::power(prev_acc, r, A_0);
        new_d = d;
        new_d *= A_0;       
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

    void verify(const flint::BigInt& element, const flint::BigMod& witness, const flint::BigMod& accumulator, const RSAKey::PublicKey& pubKey, bool &b) {
        if(witness.getModulus() != pubKey.rsaModulus || accumulator.getModulus() != pubKey.rsaModulus) {
            std::cout << "Verification failed due to modulus mismatch.\nWitness modulus was: ";
            std::cout << witness.getModulus() << std::endl;
            std::cout << "Accumulator modulus was: " << accumulator.getModulus();
            std::cout << ". Public Key modulus was: " << pubKey.rsaModulus << std::endl;
            b = false;
        }
        else{
            flint::BigInt elementRep;
            pubKey.primeRepGenerator->genRepresentative(element, elementRep);
            flint::BigMod accCandidate(pubKey.rsaModulus);
            flint::power(witness, elementRep, accCandidate);
            b = accCandidate == accumulator;
            if(!b) {
                std::cout << "Verification failed! Representative for element " << element << " was " << elementRep << std::endl;
            }
        }
    }

    /*--------------------------------Shamir Trick--------------------------------*/

    flint::BigMod shamir_trick(const flint::BigMod& Ax, const flint::BigMod& Ay, const flint::BigInt& x, const flint::BigInt& y, const RSAKey::PublicKey& publicKey){
        flint::BigMod result;
        result.setModulus(publicKey.rsaModulus);
        result = publicKey.base;

        flint::BigInt a, b;
        flint::BigMod power1, power2;
        flint::BigMod inverse_Ax, inverse_Ay;

        flint::bezout_coefficients(x, y, a, b);


        if(a<0){
            flint::BigInt positive_a = flint::BigInt(-1)*a;
            inverse_Ay = mul_inv(Ay, publicKey.rsaModulus);
            flint::power(Ax, b, power1);
            flint::power(inverse_Ay, positive_a, power2);
        }
        else if(b<0){
            flint::BigInt positive_b = flint::BigInt(-1)*b;
            inverse_Ax = mul_inv(Ax, publicKey.rsaModulus);
            flint::power(inverse_Ax, positive_b, power1);
            flint::power(Ay, a, power2);
        }
        else{
            flint::power(Ax, b, power1);
            flint::power(Ay, a, power2);
        }

        result = power1*power2;
        return result;
    }

    /*--------------------------------Batch Delete using membership witness--------------------------------*/

    void batch_delete_using_membership_proofs(const flint::BigMod& A_pre_delete, const vector<flint::BigInt>& x_list, const vector<flint::BigMod>& proofs_list, const RSAKey::PublicKey& publicKey,
                                              PrimeRepGenerator& repGen, flint::BigMod& A_post_delete, flint::BigInt& product, flint::BigMod& proof, ThreadPool& threadPool){
        size_t nMembers = x_list.size();
        vector<flint::BigInt> members(nMembers);

        genRepresentatives(x_list, repGen, members, threadPool);        

        A_post_delete = proofs_list[0];

        product = members[0];
        for(size_t i=1;i<nMembers;i++){
            A_post_delete = shamir_trick(A_post_delete, proofs_list[i], product, members[i], publicKey);
            product *= members[i];
        }
        NIPoE_Prove(repGen, A_post_delete, product, A_pre_delete, proof);
    }
    void witness_update_boneh(const flint::BigMod& A_post_delete, const flint::BigMod& prev_wit, const vector<flint::BigInt>& x_lists, 
            const vector<flint::BigInt>& y_lists, const flint::BigInt& x_k, const RSAKey& rsakey, flint::BigMod& wit_post_delete, 
            flint::BigMod& wit_final, ThreadPool& threadPool){
        
        size_t d = x_lists.size(), k = y_lists.size();
        vector<flint::BigInt> deleted_members(d), added_members(k);
        flint::BigInt x_k_rep;
        flint::BigInt product;
        flint::BigMod Q;
        PrimeRepGenerator& repGen = *(rsakey.getPublicKey().primeRepGenerator);
        
        repGen.genRepresentative(x_k, x_k_rep);
        genRepresentatives(x_lists, repGen, deleted_members, threadPool);
        product = accumulateSetHelper(deleted_members, deleted_members.size(), rsakey.getPublicKey());
        wit_post_delete = shamir_trick(A_post_delete, prev_wit, product, x_k_rep, rsakey.getPublicKey());
        
        genRepresentatives(y_lists, repGen, added_members, threadPool);
        RSAAccumulator::batchAdd (added_members, rsakey, wit_post_delete, wit_final, Q);
        
    }   

}  // namespace RSAAccumulator