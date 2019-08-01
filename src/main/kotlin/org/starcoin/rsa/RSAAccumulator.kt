package org.starcoin.rsa

import java.math.BigInteger
import kotlin.random.Random

typealias RSAProof = TwoValue<BigInteger>
typealias RSACommit = BigInteger

// Using the RSA-2048 challenge modulus.
// The factors and group order, equivalent to the private key, are believed to be unknown!
// https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
val n = BigInteger("25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357")

class RSAAccumulator {

    companion object {
        //RSA key size for 128 bits of security (modulu size)
        private const val RSA_KEY_SIZE = 3072
        private const val RSA_PRIME_SIZE = RSA_KEY_SIZE / 2
        //taken from: LLX, "Universal accumulators with efficient nonmembership proofs", construction 1
        private const val ACCUMULATED_PRIME_SIZE = 128

        @JvmStatic
        fun verifyMembership(
            commitment: BigInteger,
            proof: TwoValue<BigInteger>
        ): Boolean {
            return this.doVerifyMembership(commitment, proof.second, proof.first)
        }

        private fun doVerifyMembership(A: BigInteger, x: BigInteger, proof: BigInteger): Boolean {
            return proof.modPow(x, n) == A
        }
    }

    val A0: BigInteger
    private var A: BigInteger
    private val data = mutableMapOf<BigInteger, BigInteger>()

    val size: Int
        get() = this.data.size

    init {
        // draw random number within range of [0,n-1]
        A0 = Random.nextBigInteger(BigInteger.ZERO, n)
        A = A0
    }

    private fun getNonce(x: BigInteger): BigInteger {
        return data.getValue(x)
    }

    fun add(x: BigInteger): RSACommit {
        return if (data.containsKey(x)) {
            A
        } else {
            val (hashPrime, nonce) = hashToPrime(x, ACCUMULATED_PRIME_SIZE)
            A = A.modPow(hashPrime, n)
            data[x] = nonce
            A
        }
    }

    fun proveMembership(x: BigInteger): RSAProof {
        return this.proveMembershipOrNull(x) ?: throw NoSuchElementException("Can not find member $x")
    }

    fun proveMembershipOrNull(x: BigInteger): RSAProof? {
        return if (!data.containsKey(x)) {
            null
        } else {
            var product = BigInteger.ONE
            for ((k, v) in data) {
                if (k != x) {
                    product *= hashToPrime(k, ACCUMULATED_PRIME_SIZE, v).first
                }
            }
            RSAProof(A0.modPow(product, n), hashToPrime(x, ACCUMULATED_PRIME_SIZE, getNonce(x)).first)
        }
    }

    fun delete(x: BigInteger): RSACommit {
        return if (!data.containsKey(x)) {
            A
        } else {
            data.remove(x)
            var product = BigInteger.ONE
            for ((k, v) in data) {
                if (k != x) {
                    product *= hashToPrime(k, ACCUMULATED_PRIME_SIZE, v).first
                }
            }
            this.A = A0.modPow(product, n)
            A
        }
    }

}
