package net.corda.core.crypto

import com.sun.javaws.exceptions.InvalidArgumentException
import net.corda.core.serialization.deserialize
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.AlgorithmParameterSpec

/**
 * Dedicated class for storing a set of signatures that comprise [CompositeKey].
 */
class CompositeSignature : Signature(ALGORITHM) {
    companion object {
        val ALGORITHM = "X-Corda-CompositeSig"
    }
    private var buffer: ByteArrayOutputStream = ByteArrayOutputStream(1024)
    private var verifyKey: CompositeKey? = null

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineGetParameter(param: String?): Any {
        throw InvalidAlgorithmParameterException("Composite signatures do not support any parameters")
    }

    @Throws(InvalidKeyException::class)
    override fun engineInitSign(privateKey: PrivateKey?) {
        throw InvalidKeyException("Composite signatures must be assembled independently from signatures provided by the component private keys")
    }

    @Throws(InvalidKeyException::class)
    override fun engineInitVerify(publicKey: PublicKey?) {
        if (publicKey is CompositeKey) {
            buffer = ByteArrayOutputStream(1024)
            verifyKey = publicKey
        } else {
            throw IllegalArgumentException("Key to verify must be a composite key")
        }
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineSetParameter(param: String?, value: Any?) {
        throw InvalidAlgorithmParameterException("Composite signatures do not support any parameters")
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineSetParameter(params: AlgorithmParameterSpec) {
        throw InvalidAlgorithmParameterException("Composite signatures do not support any parameters")
    }

    @Throws(SignatureException::class)
    override fun engineSign(): ByteArray {
        throw SignatureException("Composite signatures must be assembled independently from signatures provided by the component private keys")
    }

    override fun engineUpdate(b: Byte) {
        buffer.write(b.toInt())
    }

    override fun engineUpdate(b: ByteArray?, off: Int, len: Int) {
        buffer.write(b, off, len)
    }

    @Throws(SignatureException::class)
    override fun engineVerify(sigBytes: ByteArray): Boolean {
        val sig = sigBytes.deserialize<CompositeSignatureData>()
        return if (verifyKey != null && verifyKey!!.isFulfilledBy(sig.sigs.map { it.by })) {
            val clearData = buffer.toByteArray()
            sig.sigs.all {
                return it.verifyWithECDSAInner(clearData)
            }
        } else {
            false
        }
    }
}