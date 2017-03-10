package net.corda.core.crypto

import net.corda.core.serialization.deserialize
import java.io.ByteArrayOutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec

/**
 * Dedicated class for storing a set of signatures that comprise [CompositeKey].
 */
class CompositeSignature : Signature(CompositeKey.ALGORITHM) {
    private var buffer: ByteArrayOutputStream = ByteArrayOutputStream(1024)
    private var verifyKey: CompositeKey? = null

    override fun engineGetParameter(param: String?): Any {
        throw UnsupportedOperationException("Composite keys do not support any parameters")
    }

    override fun engineInitSign(privateKey: PrivateKey?) {
        throw UnsupportedOperationException("Composite signatures must be assembled independently from signatures provided by the component private keys")
    }

    override fun engineInitVerify(publicKey: PublicKey?) {
        if (publicKey is CompositeKey) {
            buffer = ByteArrayOutputStream(1024)
            verifyKey = publicKey
        } else {
            throw IllegalArgumentException("Key to verify must be a composite key")
        }
    }

    override fun engineSetParameter(param: String?, value: Any?) {
        throw UnsupportedOperationException("Composite keys do not support any parameters")
    }

    override fun engineSetParameter(params: AlgorithmParameterSpec) {
        throw UnsupportedOperationException("Composite keys do not support any parameters")
    }

    override fun engineSign(): ByteArray {
        throw UnsupportedOperationException("Composite signatures must be assembled independently from signatures provided by the component private keys")
    }

    override fun engineUpdate(b: Byte) {
        buffer.write(b.toInt())
    }

    override fun engineUpdate(b: ByteArray?, off: Int, len: Int) {
        buffer.write(b, off, len)
    }

    override fun engineVerify(sigBytes: ByteArray): Boolean {
        val sig = sigBytes.deserialize<CompositeSignatureData>()
        return if (verifyKey != null && verifyKey!!.isFulfilledBy(sig.sigs.map { it.by })) {
            val clearData = buffer.toByteArray()
            sig.sigs.all {
                return try {
                    it.verifyWithECDSA(clearData)
                    true
                } catch(ex: IllegalStateException) {
                    false
                }
            }
        } else {
            false
        }
    }
}