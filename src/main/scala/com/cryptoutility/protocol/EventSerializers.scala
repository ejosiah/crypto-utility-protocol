package com.cryptoutility.protocol

import java.io.{ByteArrayInputStream, DataInputStream, ByteArrayOutputStream, DataOutputStream}
import java.math.BigInteger
import java.security.{KeyFactory, PublicKey}
import java.security.spec.RSAPublicKeySpec

import Events.{UserInfo, Event, InvalidFormatException}

import scala.collection.mutable.ArrayBuffer
import scala.util.control.NonFatal
import scala.util.{Success, Failure, Try}
import Events._
/**
  * Created by jay on 23/09/2016.
  */
object EventSerializer {
  type Header = Map[String, String]
  val EOF: Int = -1
  val IntSize = 4 //bytes
  val HeaderSize = 8 //bytes

  def toBytes(i: Int): Array[Byte] = {
    Array(
      ((i >>> 24) & 0xFF).asInstanceOf[Byte],
      ((i >>> 16) & 0xFF).asInstanceOf[Byte],
      ((i >>>  8) & 0xFF).asInstanceOf[Byte],
      ((i >>>  0) & 0xFF).asInstanceOf[Byte]
    )
  }

  def readInt(data: Array[Byte]): Int = {
    if(data.length < 4) throw new IllegalArgumentException(s"Not enough byte, 4 bytes required")
    (data(0) << 24) + ( data(1) << 16) + (data(2) << 8) + (data(3) << 0)
  }

  def writeKey(out: DataOutputStream, user: UserInfo) = {
    val keySpec = KeyFactory.getInstance("RSA").getKeySpec(user.key, classOf[RSAPublicKeySpec])
    out.writeUTF(keySpec.getModulus.toString) // to Byte array would be better
    out.writeUTF(keySpec.getPublicExponent.toString)
  }

  def serializeUser(out: DataOutputStream, user: UserInfo) = {
    out.writeUTF(user.fname)
    out.writeUTF(user.lname)
    out.writeUTF(user.email)
    writeKey(out, user)
    out.writeUTF(user.clientId)
  }

  def deserializeUser(in: DataInputStream, isNew: Boolean) = {
    val fname = in.readUTF()
    val lname = in.readUTF()
    val email = in.readUTF()
    val pubKey = extractKey(in)
    val clientId = in.readUTF()
    UserInfo(fname, lname, email, pubKey, clientId)
  }

  private def extractKey(in: DataInputStream): PublicKey = {
    val modulus = new BigInteger(in.readUTF())
    val exponent = new BigInteger(in.readUTF())
    val keySpec = new RSAPublicKeySpec(modulus, exponent)
    KeyFactory.getInstance("RSA").generatePublic(keySpec)
  }

  def serialize(event: Event): Array[Byte] = {
    val body = event match{
      case e: Initialized => InitializedSerializer.serialize(e)
      case e: UserCreated => UserCreatedSerializer.serialize(e)
    }
    val header = new ArrayBuffer[Byte](HeaderSize)
    header ++= toBytes(HeaderSize + body.length)
    header ++= toBytes(id(event))

    (header ++= body).toArray
  }

  def deserialize(data: Array[Byte]): Event = {
    val buf = ArrayBuffer(data:_*)
    val eventId = readInt(buf.slice(IntSize, HeaderSize).toArray)
    val body = buf.slice(HeaderSize, buf.size).toArray
    (eventId, body) match {
      case (0, b) => InitializedSerializer.deserialize(b)
      case(1, b) => UserCreatedSerializer.deserialize(b)
      case _ => throw InvalidFormatException()
    }
  }

}

import EventSerializer._


sealed trait EventSerializer[E <: Event]{
  def serialize(evt: E): Array[Byte]

  def deserialize(data: Array[Byte]): E

  def write(f: DataOutputStream => Unit) = {
    val byteStream = new ByteArrayOutputStream(1024)
    val out = new DataOutputStream(byteStream)
    f(out)
    byteStream.toByteArray
  }

  def read[T <: E](data: Array[Byte])(f: DataInputStream => T) = {
    val in = new DataInputStream(new ByteArrayInputStream(data))
    Try (f(in)) match {
      case Failure(NonFatal(e)) =>
        val e1 = InvalidFormatException()
        e1.addSuppressed(e)
        throw e
      case Success(res) => res
    }
  }

}

object InitializedSerializer extends EventSerializer[Initialized]{

  override def serialize(evt: Initialized): Array[Byte] = write{ out =>
    out.writeBoolean(evt.isNew)
    serializeUser(out, evt.user)
  }

  def deserialize(data: Array[Byte]): Initialized = read(data){ in =>
    val isNew = in.readBoolean()
    val user = deserializeUser(in, isNew)
    Initialized(isNew, user)
  }
}

object UserCreatedSerializer extends EventSerializer[UserCreated]{

  def serialize(event: UserCreated): Array[Byte] = write( serializeUser(_, event.user))

  def deserialize(data: Array[Byte]): UserCreated = read(data)(in => UserCreated(deserializeUser(in, isNew = false)))
}

abstract class StreamEventSerializer[E <: StreamEvent] extends EventSerializer[E]{

  def serialize(evt: E): Array[Byte] = write{ out =>
    out.write(evt.chunk)
  }

  def deserialize(data: Array[Byte]): E = read(data){ in =>
    val size = in.readInt()
    val buf = new Array[Byte](size)
    in.readFully(buf)
    construct(size, buf)
  }

  def construct(size: Int, buf: Array[Byte]): E

}

object StreamStaredSerializer extends StreamEventSerializer[StreamStarted]{
  override def construct(size: Int, buf: Array[Byte]): StreamStarted = new StreamStarted()
}

object StreamPartSerializer extends StreamEventSerializer[StreamPart] {
  override def construct(size: Int, buf: Array[Byte]): StreamPart = new StreamPart(buf, size)
}

object StreamEndedSerializer extends StreamEventSerializer[StreamEnded]{
  override def construct(size: Int, buf: Array[Byte]): StreamEnded = new StreamEnded()
}
