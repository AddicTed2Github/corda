// Generated file do not edit, generated by io.requery.processor.EntityProcessor
package net.corda.node.services.vault.schemas;

import io.requery.Persistable;
import io.requery.meta.AttributeBuilder;
import io.requery.meta.AttributeDelegate;
import io.requery.meta.Type;
import io.requery.meta.TypeBuilder;
import io.requery.proxy.EntityProxy;
import io.requery.proxy.LongProperty;
import io.requery.proxy.Property;
import io.requery.proxy.PropertyState;
import io.requery.util.function.Function;
import io.requery.util.function.Supplier;
import java.lang.Long;
import java.lang.Object;
import java.lang.Override;
import java.lang.String;
import javax.annotation.Generated;

@Generated("io.requery.processor.EntityProcessor")
public class VaultCashBalancesEntity implements VaultSchema.VaultCashBalances, Persistable {
    public static final AttributeDelegate<VaultCashBalancesEntity, String> CURRENCY = new AttributeDelegate(
    new AttributeBuilder<VaultCashBalancesEntity, String>("currency_code", String.class)
    .setProperty(new Property<VaultCashBalancesEntity, String>() {
        @Override
        public String get(VaultCashBalancesEntity entity) {
            return entity.currency;
        }

        @Override
        public void set(VaultCashBalancesEntity entity, String value) {
            entity.currency = value;
        }
    })
    .setPropertyName("getCurrency")
    .setPropertyState(new Property<VaultCashBalancesEntity, PropertyState>() {
        @Override
        public PropertyState get(VaultCashBalancesEntity entity) {
            return entity.$currency_state;
        }

        @Override
        public void set(VaultCashBalancesEntity entity, PropertyState value) {
            entity.$currency_state = value;
        }
    })
    .setKey(true)
    .setGenerated(false)
    .setLazy(false)
    .setNullable(true)
    .setUnique(false)
    .setLength(3)
    .build());

    public static final AttributeDelegate<VaultCashBalancesEntity, Long> AMOUNT = new AttributeDelegate(
    new AttributeBuilder<VaultCashBalancesEntity, Long>("amount", long.class)
    .setProperty(new LongProperty<VaultCashBalancesEntity>() {
        @Override
        public Long get(VaultCashBalancesEntity entity) {
            return entity.amount;
        }

        @Override
        public void set(VaultCashBalancesEntity entity, Long value) {
            if(value != null) {
                entity.amount = value;
            }
        }

        @Override
        public long getLong(VaultCashBalancesEntity entity) {
            return entity.amount;
        }

        @Override
        public void setLong(VaultCashBalancesEntity entity, long value) {
            entity.amount = value;
        }
    })
    .setPropertyName("getAmount")
    .setPropertyState(new Property<VaultCashBalancesEntity, PropertyState>() {
        @Override
        public PropertyState get(VaultCashBalancesEntity entity) {
            return entity.$amount_state;
        }

        @Override
        public void set(VaultCashBalancesEntity entity, PropertyState value) {
            entity.$amount_state = value;
        }
    })
    .setGenerated(false)
    .setLazy(false)
    .setNullable(true)
    .setUnique(false)
    .setDefaultValue("0")
    .build());

    public static final Type<VaultCashBalancesEntity> $TYPE = new TypeBuilder<VaultCashBalancesEntity>(VaultCashBalancesEntity.class, "vault_cash_balances")
    .setBaseType(VaultSchema.VaultCashBalances.class)
    .setCacheable(true)
    .setImmutable(false)
    .setReadOnly(false)
    .setStateless(false)
    .setView(false)
    .setFactory(new Supplier<VaultCashBalancesEntity>() {
        @Override
        public VaultCashBalancesEntity get() {
            return new VaultCashBalancesEntity();
        }
    })
    .setProxyProvider(new Function<VaultCashBalancesEntity, EntityProxy<VaultCashBalancesEntity>>() {
        @Override
        public EntityProxy<VaultCashBalancesEntity> apply(VaultCashBalancesEntity entity) {
            return entity.$proxy;
        }
    })
    .addAttribute(CURRENCY)
    .addAttribute(AMOUNT)
    .build();

    private PropertyState $currency_state;

    private PropertyState $amount_state;

    private String currency;

    private long amount;

    private final transient EntityProxy<VaultCashBalancesEntity> $proxy = new EntityProxy<VaultCashBalancesEntity>(this, $TYPE);

    public VaultCashBalancesEntity() {
    }

    @Override
    public String getCurrency() {
        return $proxy.get(CURRENCY);
    }

    public void setCurrency(String currency) {
        $proxy.set(CURRENCY, currency);
    }

    @Override
    public long getAmount() {
        return $proxy.get(AMOUNT);
    }

    public void setAmount(long amount) {
        $proxy.set(AMOUNT, amount);
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof VaultCashBalancesEntity && ((VaultCashBalancesEntity)obj).$proxy.equals(this.$proxy);
    }

    @Override
    public int hashCode() {
        return $proxy.hashCode();
    }

    @Override
    public String toString() {
        return $proxy.toString();
    }
}
