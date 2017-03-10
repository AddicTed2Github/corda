package net.corda.core.crypto

import net.corda.core.serialization.OpaqueBytes
import net.corda.core.serialization.serialize
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CompositeKeyTests {
    val aliceKey = generateKeyPair()
    val bobKey = generateKeyPair()
    val charlieKey = generateKeyPair()

    val alicePublicKey = aliceKey.public.composite
    val bobPublicKey = bobKey.public
    val charliePublicKey = charlieKey.public.composite

    val message = OpaqueBytes("Transaction".toByteArray())

    val aliceSignature = aliceKey.signWithECDSA(message)
    val bobSignature = bobKey.signWithECDSA(message)
    val charlieSignature = charlieKey.signWithECDSA(message)
    val compositeAliceSignature = CompositeSignatureData(listOf(aliceSignature))

    @Test
    fun `(Alice) fulfilled by Alice signature`() {
        assertTrue { alicePublicKey.isFulfilledBy(aliceSignature.by) }
        assertFalse { alicePublicKey.isFulfilledBy(charlieSignature.by) }
    }

    @Test
    fun `(Alice or Bob) fulfilled by either signature`() {
        val aliceOrBob = CompositeKey.Builder().addKeys(alicePublicKey, bobPublicKey).build(threshold = 1)
        assertTrue { aliceOrBob.isFulfilledBy(aliceSignature.by) }
        assertTrue { aliceOrBob.isFulfilledBy(bobSignature.by) }
    }

    @Test
    fun `(Alice and Bob) fulfilled by Alice, Bob signatures`() {
        val aliceAndBob = CompositeKey.Builder().addKeys(alicePublicKey, bobPublicKey).build()
        val signatures = listOf(aliceSignature, bobSignature)
        assertTrue { aliceAndBob.isFulfilledBy(signatures.byKeys()) }
    }

    @Test
    fun `(Alice and Bob) not fulfilled by neither signature alone`() {
        val aliceAndBob = CompositeKey.Builder().addKeys(alicePublicKey, bobPublicKey).build()
        assertFalse { aliceAndBob.isFulfilledBy(listOf(aliceSignature).byKeys()) }
        assertFalse { aliceAndBob.isFulfilledBy(listOf(bobSignature).byKeys()) }
    }

    @Test
    fun `((Alice and Bob) or Charlie) signature verifies`() {
        // TODO: Look into a DSL for building multi-level composite keys if that becomes a common use case
        val aliceAndBob = CompositeKey.Builder().addKeys(alicePublicKey, bobPublicKey).build()
        val aliceAndBobOrCharlie = CompositeKey.Builder().addKeys(aliceAndBob, charliePublicKey).build(threshold = 1)

        val signatures = listOf(aliceSignature, bobSignature)

        assertTrue { aliceAndBobOrCharlie.isFulfilledBy(signatures.byKeys()) }
    }

    @Test
    fun `encoded tree decodes correctly`() {
        val aliceAndBob = CompositeKey.Builder().addKeys(alicePublicKey, bobPublicKey).build()
        val aliceAndBobOrCharlie = CompositeKey.Builder().addKeys(aliceAndBob, charliePublicKey).build(threshold = 1)

        val encoded = aliceAndBobOrCharlie.toBase58String()
        val decoded = parsePublicKeyBase58(encoded)

        assertEquals(decoded, aliceAndBobOrCharlie)
    }

    /**
     * Check that verifying a composite signature using the [CompositeSignature] engine works.
     */
    @Test
    fun `composite signature verification`() {
        val engine = CompositeSignature()
        val signature = CompositeSignatureData(listOf(aliceSignature))
        val wrongSignature = CompositeSignatureData(listOf(charlieSignature))
        engine.initVerify(alicePublicKey)
        engine.update(message.bytes)
        assertTrue { engine.verify(signature.serialize().bytes) }
        assertFalse { engine.verify(wrongSignature.serialize().bytes) }
    }
}
