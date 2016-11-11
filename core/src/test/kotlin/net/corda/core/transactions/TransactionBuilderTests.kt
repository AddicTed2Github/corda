package net.corda.core.transactions

import com.esotericsoftware.kryo.KryoException
import net.corda.core.contracts.*
import net.corda.core.crypto.CompositeKey
import net.corda.core.utilities.DUMMY_NOTARY
import net.corda.testing.ALICE_KEY
import net.corda.testing.ALICE_PUBKEY
import net.corda.testing.BOB_PUBKEY
import org.junit.Test
import java.security.PublicKey
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Basic functionality tests for the transaction builder.
 */
class TransactionBuilderTests {
    @Test
    fun `basic transaction assembly`() {
        val input = DummyContract.SingleOwnerState(11112016, ALICE_PUBKEY)
        val output = DummyContract.SingleOwnerState(20161111, BOB_PUBKEY)
        val command = DummyContract.Commands.Move()
        val inputRef = StateAndRef(TransactionState(input, DUMMY_NOTARY), StateRef(input.hash(), 0))
        val builder = TransactionType.General.Builder(DUMMY_NOTARY)
        builder.addCommand(command, ALICE_PUBKEY)
        builder.addInputState(inputRef)
        builder.addOutputState(output)
        builder.signWith(ALICE_KEY)
        val tx = builder.toWireTransaction()

        assertEquals(1, tx.inputs.size)
        assertEquals(1, tx.outputs.size)
        assertEquals(1, tx.commands.size)
        assertEquals(DUMMY_NOTARY, tx.notary)
        assertEquals(inputRef.ref, tx.inputs[0])
        assertEquals(output, tx.outputs[0].data)
        assertEquals(DUMMY_NOTARY, tx.outputs[0].notary)
        assertEquals(command, tx.commands.single().value)
        assertEquals(ALICE_PUBKEY, tx.commands.single().signers.single())
        assert(tx.attachments.isEmpty())
    }

    @Test
    fun `serialization checks`() {
        val data = HashMap<String, String>()
        data.put("Mary", "had")
        data.put("little", "lamb")
        data.put("fleece", "white")
        val unstableState = UnstableState(data)
        val nonVerifyingBuilder = TransactionType.General.Builder(DUMMY_NOTARY, EnumSet.noneOf(TransactionBuilder.Option::class.java))
        val verifyingBuilder = TransactionType.General.Builder(DUMMY_NOTARY, EnumSet.of(TransactionBuilder.Option.CHECK_SERIALIZATION))
        nonVerifyingBuilder.addOutputState(unstableState)
        assertFailsWith<KryoException> {
            verifyingBuilder.addOutputState(unstableState)
        }
    }

    data class UnstableState(val setOfData: Map<String, String>) : ContractState {
        override val contract: Contract = DummyContract()
        override val participants: List<CompositeKey> = emptyList()
    }
}
