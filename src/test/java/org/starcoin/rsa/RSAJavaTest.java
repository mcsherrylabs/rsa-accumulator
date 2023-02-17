package org.starcoin.rsa;

import kotlin.random.Random;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class RSAJavaTest {

    @Test
    public void testRSAAccumulatorSimple() {
        RSAAccumulator accumulator = new RSAAccumulator();
        BigInteger x0 = new BigInteger(Random.Default.nextBytes(128));
        BigInteger commit1 = accumulator.add(x0);
        TwoValue<BigInteger> proof0 = accumulator.proveMembership(x0);

        Assert.assertEquals(accumulator.getSize(), 1);
        Assert.assertEquals(accumulator.getA0(), proof0.getFirst());
        Assert.assertTrue(RSAAccumulator.verifyMembership(commit1, proof0));
    }


    private BigInteger[] generateManyKeys(int howMany) {
        BigInteger[] keys = new BigInteger[howMany];
        for (int i = 0; i < howMany; i++) {
            keys[i] = new BigInteger(Random.Default.nextBytes(512));
            System.out.println("Generated key " + i);
        }
        return keys;
    }

    private BigInteger accumulateKeys(RSAAccumulator accumulator, BigInteger[] keys) {

        assert keys.length > 0;

        BigInteger result = null;

        for (int i = 0; i < keys.length; i++) {
            result = accumulator.add(keys[i]);
        }
        return result;
    }

    private TwoValue<BigInteger>[] accumulateProofs(RSAAccumulator accumulator, BigInteger[] keys) {

        TwoValue<BigInteger>[] result = new TwoValue[keys.length];

        for (int i = 0; i < keys.length; i++) {
            result[i] = accumulator.proveMembership(keys[i]);
        }
        return result;
    }

    @Test
    public void testRSAAccumulator() {
        RSAAccumulator accumulator = new RSAAccumulator();

        int howMany = 500;
        BigInteger[] manyKeys = generateManyKeys(howMany);

        //BigInteger x0 = new BigInteger(Random.Default.nextBytes(128));
        BigInteger commit1 = accumulateKeys(accumulator, manyKeys);

        TwoValue<BigInteger>[] proofs = accumulateProofs(accumulator, manyKeys);

        Assert.assertEquals(accumulator.getSize(), howMany);
        //Assert.assertEquals(accumulator.getA0(), proofs.getFirst()); <-- what's this?

        for (int i = 0; i < howMany; i++) {
            Assert.assertTrue(RSAAccumulator.verifyMembership(commit1, proofs[i]));
        }

        BigInteger newAcc = commit1;

        for (int i = 0; i < manyKeys.length; i++) {
            System.out.println("Acc bitlen is " + newAcc.bitLength());
            TwoValue<BigInteger> proof = accumulator.proveMembership(manyKeys[i]);
            Assert.assertTrue(RSAAccumulator.verifyMembership(newAcc, proof));
            Assert.assertTrue(accumulator.getSize() == manyKeys.length - i);
            newAcc = accumulator.delete(manyKeys[i]);
            Assert.assertFalse(RSAAccumulator.verifyMembership(newAcc, proof));
            newAcc = accumulator.delete(manyKeys[i]); // delete again to be sure it doesm't cause an issue
            Assert.assertFalse(RSAAccumulator.verifyMembership(newAcc, proof));
        }

    }
}
