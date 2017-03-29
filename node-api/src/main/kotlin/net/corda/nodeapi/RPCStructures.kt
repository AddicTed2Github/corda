@file:JvmName("RPCStructures")

package net.corda.nodeapi

import com.esotericsoftware.kryo.Kryo
import com.esotericsoftware.kryo.Registration
import com.esotericsoftware.kryo.Serializer
import com.esotericsoftware.kryo.io.Input
import com.esotericsoftware.kryo.io.Output
import com.google.common.util.concurrent.ListenableFuture
import net.corda.core.flows.FlowException
import net.corda.core.serialization.*
import net.corda.core.toFuture
import net.corda.core.toObservable
import org.apache.commons.fileupload.MultipartStream
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import rx.Notification
import rx.Observable

/** Global RPC logger */
val rpcLog: Logger by lazy { LoggerFactory.getLogger("net.corda.rpc") }

/** Used in the RPC wire protocol to wrap an observation with the handle of the observable it's intended for. */
data class MarshalledObservation(val forHandle: Int, val what: Notification<*>)

data class User(val username: String, val password: String, val permissions: Set<String>) {
    override fun toString(): String = "${javaClass.simpleName}($username, permissions=$permissions)"
}

/** Records the protocol version in which this RPC was added. */
@Target(AnnotationTarget.FUNCTION)
@MustBeDocumented
annotation class RPCSinceVersion(val version: Int)

/** The contents of an RPC request message, separated from the MQ layer. */
data class ClientRPCRequestMessage(
        val args: SerializedBytes<Array<Any>>,
        val replyToAddress: String,
        val observationsToAddress: String?,
        val methodName: String,
        val user: User
) {
    companion object {
        const val REPLY_TO = "reply-to"
        const val OBSERVATIONS_TO = "observations-to"
        const val METHOD_NAME = "method-name"
    }
}

/**
 * This is available to RPC implementations to query the validated [User] that is calling it. Each user has a set of
 * permissions they're entitled to which can be used to control access.
 */
@JvmField
val CURRENT_RPC_USER: ThreadLocal<User> = ThreadLocal()

/**
 * Thrown to indicate a fatal error in the RPC system itself, as opposed to an error generated by the invoked
 * method.
 */
@CordaSerializable
open class RPCException(msg: String, cause: Throwable?) : RuntimeException(msg, cause) {
    constructor(msg: String) : this(msg, null)

    class DeadlineExceeded(rpcName: String) : RPCException("Deadline exceeded on call to $rpcName")
}

object ClassSerializer : Serializer<Class<*>>() {
    override fun read(kryo: Kryo, input: Input, type: Class<Class<*>>): Class<*> {
        val className = input.readString()
        return Class.forName(className)
    }

    override fun write(kryo: Kryo, output: Output, clazz: Class<*>) {
        output.writeString(clazz.name)
    }
}

@CordaSerializable
class PermissionException(msg: String) : RuntimeException(msg)

object RPCKryoClientKey
object RPCKryoDispatcherKey
object RPCKryoQNameKey
object RPCKryoMethodNameKey
object RPCKryoLocationKey

// The Kryo used for the RPC wire protocol. Every type in the wire protocol is listed here explicitly.
// This is annoying to write out, but will make it easier to formalise the wire protocol when the time comes,
// because we can see everything we're using in one place.
class RPCKryo(observableSerializer: Serializer<Observable<Any>>) : CordaKryo(makeStandardClassResolver()) {
    init {
        DefaultKryoCustomizer.customize(this)

        // RPC specific classes
        register(Class::class.java, ClassSerializer)
        register(MultipartStream.ItemInputStream::class.java, InputStreamSerializer)
        register(MarshalledObservation::class.java, ImmutableClassSerializer(MarshalledObservation::class))
        register(Observable::class.java, observableSerializer)
        @Suppress("UNCHECKED_CAST")
        register(ListenableFuture::class,
                read = { kryo, input -> observableSerializer.read(kryo, input, Observable::class.java as Class<Observable<Any>>).toFuture() },
                write = { kryo, output, obj -> observableSerializer.write(kryo, output, obj.toObservable()) }
        )
        register(
                FlowException::class,
                read = { kryo, input ->
                    val message = input.readString()
                    val cause = kryo.readObjectOrNull(input, Throwable::class.java)
                    FlowException(message, cause)
                },
                write = { kryo, output, obj ->
                    // The subclass may have overridden toString so we use that
                    val message = if (obj.javaClass != FlowException::class.java) obj.toString() else obj.message
                    output.writeString(message)
                    kryo.writeObjectOrNull(output, obj.cause, Throwable::class.java)
                }
        )
    }

    override fun getRegistration(type: Class<*>): Registration {
        if (Observable::class.java != type && Observable::class.java.isAssignableFrom(type)) {
            return super.getRegistration(Observable::class.java)
        }
        if (ListenableFuture::class.java != type && ListenableFuture::class.java.isAssignableFrom(type)) {
            return super.getRegistration(ListenableFuture::class.java)
        }
        if (FlowException::class.java.isAssignableFrom(type))
            return super.getRegistration(FlowException::class.java)
        return super.getRegistration(type)
    }
}
