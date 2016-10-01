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
    ((data(0) & 0xFF) << 24) + ((data(1) & 0xFF) << 16) + ((data(2) & 0xFF) << 8) + ((data(3) & 0xFF) << 0)
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
      case e: StreamStarted => StreamStaredSerializer.serialize(e)
      case e: StreamPart => StreamPartSerializer.serialize(e)
      case e: StreamEnded => StreamEndedSerializer.serialize(e)
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
      case (InitializedId, b) => InitializedSerializer.deserialize(b)
      case (UserCreatedId, b) => UserCreatedSerializer.deserialize(b)
      case (StreamStartedId, b) => StreamStaredSerializer.deserialize(b)
      case (StreamPartId, b) => StreamPartSerializer.deserialize(b)
      case (StreamEndedId, b) => StreamEndedSerializer.deserialize(b)
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

object StreamPartSerializer extends EventSerializer[StreamPart]{

  def serialize(evt: StreamPart): Array[Byte] = write{ out =>
    out.writeLong(evt.seqId)
    out.write(evt.chunk)
  }

  def deserialize(data: Array[Byte]): StreamPart = read(data){ in =>
    val seqId = in.readLong()
    val size = in.available()
    val buf = new Array[Byte](size)
    in.readFully(buf)
    new StreamPart(seqId, buf)
  }

}

object StreamStaredSerializer extends EventSerializer[StreamStarted]{
  override def serialize(event: StreamStarted): Array[Byte] = write{ out =>
    out.writeUTF(event.secret)
    out.writeUTF(event.filename)
    out.writeUTF(event.contentType)
    out.writeUTF(event.from)
  }

  override def deserialize(data: Array[Byte]): StreamStarted = read(data){ in =>
    val secret = in.readUTF()
    val filename = in.readUTF()
    val contentType = in.readUTF()
    val from = in.readUTF()
    new StreamStarted(filename, contentType, from, secret)
  }
}



object StreamEndedSerializer extends EventSerializer[StreamEnded]{
  override def serialize(evt: StreamEnded): Array[Byte] = write{ out =>
    out.writeLong(evt.size)
    out.writeUTF(evt.checksum)
  }

  override def deserialize(data: Array[Byte]): StreamEnded = read(data){ in =>
    val size = in.readLong()
    val checksum = in.readUTF()
    new StreamEnded(size, checksum)
  }
}
