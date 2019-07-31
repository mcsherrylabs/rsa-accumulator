package org.starcoin.rsa

import org.junit.Assert
import org.junit.Test
import kotlin.random.Random


class RSAAccumulatorTest {

    @Test
    fun testAddAndProve() {
        // first addition
        val accumulator = RSAAccumulator()
        val x1 = Random.nextBigInteger()
        val x2 = Random.nextBigInteger()

        val commit1 = accumulator.add(x1)
        val proof1 = accumulator.proveMembership(x1)

        Assert.assertEquals(accumulator.size, 1)
        Assert.assertEquals(accumulator.A0, proof1.first)
        Assert.assertTrue(RSAAccumulator.verifyMembership(commit1, x1, proof1))

        // second addition

        val commit2 = accumulator.add(x2)
        val proof2 = accumulator.proveMembership(x2)

        Assert.assertEquals(accumulator.size, 2)
        Assert.assertEquals(commit1, proof2.first)
        Assert.assertTrue(RSAAccumulator.verifyMembership(commit2, x2, proof2))

        // delete
        val commit3 = accumulator.delete(x1)
        val proof3 = accumulator.proveMembership(x2)
        val proofNone = accumulator.proveMembershipOrNull(x1)

        Assert.assertEquals(accumulator.size, 1)
        Assert.assertNull(proofNone)
        Assert.assertTrue(RSAAccumulator.verifyMembership(commit3, x2, proof3))

    }

}