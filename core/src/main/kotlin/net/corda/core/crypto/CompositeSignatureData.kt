package net.corda.core.crypto

import net.corda.core.serialization.CordaSerializable

/**
 * Custom class for holding signature data. This exists for later extension work to provide a standardised cross-platform
 * serialization format (i.e. not Kryo).
 */
@CordaSerializable
data class CompositeSignatureData(val sigs: List<DigitalSignature.WithKey>) {
    companion object {
        val EMPTY = CompositeSignatureData(emptyList())
    }
}
