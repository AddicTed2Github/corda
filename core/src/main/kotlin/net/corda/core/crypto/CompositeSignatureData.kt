package net.corda.core.crypto

import net.corda.core.serialization.CordaSerializable

@CordaSerializable
data class CompositeSignatureData(val sigs: List<DigitalSignature.WithKey>) {
    companion object {
        val EMPTY = CompositeSignatureData(emptyList())
    }
}
