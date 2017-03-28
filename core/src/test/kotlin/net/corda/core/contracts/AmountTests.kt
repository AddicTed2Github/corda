package net.corda.core.contracts

import org.junit.Test
import java.math.BigDecimal
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Tests of the [Amount] class.
 */
class AmountTests {
    @Test
    fun basicCurrency() {
        val expected = 1000L
        val amount = Amount(expected, GBP)
        assertEquals(expected, amount.quantity)
    }

    @Test
    fun decimalConversion() {
        val quantity = 1234L
        val amountGBP = Amount(quantity, GBP)
        val expectedGBP = BigDecimal("12.34")
        assertEquals(expectedGBP, amountGBP.toDecimal())
        assertEquals(amountGBP, Amount.fromDecimal(amountGBP.toDecimal(), amountGBP.token))
        val amountJPY = Amount(quantity, JPY)
        val expectedJPY = BigDecimal("1234")
        assertEquals(expectedJPY, amountJPY.toDecimal())
        assertEquals(amountJPY, Amount.fromDecimal(amountJPY.toDecimal(), amountJPY.token))
        val testAsset = TestAsset("GB0009997999")
        val amountBond = Amount(quantity, testAsset)
        val expectedBond = BigDecimal("123400")
        assertEquals(expectedBond, amountBond.toDecimal())
        assertEquals(amountBond, Amount.fromDecimal(amountBond.toDecimal(), amountBond.token))
    }

    data class TestAsset(val name: String) : TokenizableAssetInfo {
        override val displayTokenSize: BigDecimal = BigDecimal("100")
        override fun toString(): String = name
    }

    @Test
    fun parsing() {
        assertEquals(Amount(1234L, GBP), Amount.parseCurrency("£12.34"))
        assertEquals(Amount(1200L, GBP), Amount.parseCurrency("£12"))
        assertEquals(Amount(1000L, USD), Amount.parseCurrency("$10"))
        assertEquals(Amount(5000L, JPY), Amount.parseCurrency("¥5000"))
        assertEquals(Amount(500000L, RUB), Amount.parseCurrency("₽5000"))
        assertEquals(Amount(1500000000L, CHF), Amount.parseCurrency("15,000,000 CHF"))
    }

    @Test
    fun rendering() {
        assertEquals("5000 JPY", Amount.parseCurrency("¥5000").toString())
        assertEquals("50.12 USD", Amount.parseCurrency("$50.12").toString())
    }

    @Test
    fun split() {
        for (baseQuantity in 0..1000) {
            val baseAmount = Amount(baseQuantity.toLong(), GBP)
            for (partitionCount in 1..100) {
                val splits = baseAmount.splitEvenly(partitionCount)
                assertEquals(partitionCount, splits.size)
                assertEquals(baseAmount, splits.sumOrZero(baseAmount.token))
                val min = splits.min()!!
                val max = splits.max()!!
                assertTrue(max.quantity - min.quantity <= 1L, "Amount quantities should differ by at most one token")
            }
        }
    }
}