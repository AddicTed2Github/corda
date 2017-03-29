package net.corda.node.services

import net.corda.core.crypto.*
import net.corda.core.serialization.serialize
import net.corda.node.services.identity.InMemoryIdentityService
import net.corda.testing.*
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.cert.CertPath
import java.security.cert.CertPathBuilder
import java.security.cert.X509Certificate
import java.util.*
import javax.security.auth.Subject
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Tests for the in memory identity service.
 */
class InMemoryIdentityServiceTests {

    @Test
    fun `get all identities`() {
        val service = InMemoryIdentityService()
        assertNull(service.getAllIdentities().firstOrNull())
        service.registerIdentity(ALICE)
        var expected = setOf(ALICE)
        var actual = service.getAllIdentities().toHashSet()
        assertEquals(expected, actual)

        // Add a second party and check we get both back
        service.registerIdentity(BOB)
        expected = setOf(ALICE, BOB)
        actual = service.getAllIdentities().toHashSet()
        assertEquals(expected, actual)
    }

    @Test
    fun `get identity by key`() {
        val service = InMemoryIdentityService()
        assertNull(service.partyFromKey(ALICE_PUBKEY))
        service.registerIdentity(ALICE)
        assertEquals(ALICE, service.partyFromKey(ALICE_PUBKEY))
        assertNull(service.partyFromKey(BOB_PUBKEY))
    }

    @Test
    fun `get identity by name with no registered identities`() {
        val service = InMemoryIdentityService()
        assertNull(service.partyFromName(ALICE.name))
    }

    @Test
    fun `get identity by name`() {
        val service = InMemoryIdentityService()
        val identities = listOf("Node A", "Node B", "Node C").map { Party(it, generateKeyPair().public) }
        assertNull(service.partyFromName(identities.first().name))
        identities.forEach { service.registerIdentity(it) }
        identities.forEach { assertEquals(it, service.partyFromName(it.name)) }
    }

    @Test
    fun `assert anonymous key owned by identity`() {
        val service = InMemoryIdentityService()
        val identityKey = generateKeyPair()
        val identity = Party("ou=Node A", identityKey.public)
        val txIdentity = AnonymousParty(generateKeyPair().public)
        val issuer = X500Name(identity.name)
        val serial = BigInteger.ONE
        val notBefore = Date()
        val notAfter = Date(notBefore.getTime() + 24 * 60 * 60 * 1000L)
        val subject = issuer
        val publicKeyInfo = SubjectPublicKeyInfo(CompositeKey.ALGORITHM_IDENTIFIER, identityKey.public)
        val certBuilder = X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKeyInfo)
        val signer = object : ContentSigner() {
            private val stream = ByteArrayOutputStream()
            override fun getAlgorithmIdentifier(): AlgorithmIdentifier = CompositeKey.ALGORITHM_IDENTIFIER
            override fun getOutputStream(): OutputStream = stream
            override fun getSignature(): ByteArray {
                val signature = DigitalSignature.WithKey(identityKey.public, identityKey.sign(stream.toByteArray()))
                return signature.serialize().bytes
            }
        }
        val certificate = certBuilder.build(signer)
        val certPathBuilder = CertPathBuilder.getInstance("PKIX")
        val certSelector = X509CertSelector()
        certSelector.setCertificate(certificate)
        PKIXBuilderParameters cpp = new PKIXBuilderParameters(trustAnchors, certSelector)
        cpp.addCertStore(cs)
        cpp.setRevocationEnabled(true)
        cpp.setMaxPathLength(6)
        cpp.setDate(new Date())

        // TODO: Check we can't assert ownership without registering the path first
        service.registerPath(identity, txIdentity, certPathBuilder.build(cpp).certPath)
        service.assertOwnership(identity, txIdentity)
    }
}