package com.cryptoutility.protocol.crypto

import java.io.{ByteArrayInputStream, InputStream, FileInputStream, File}
import java.security.{MessageDigest, PrivateKey, PublicKey, Key}
import java.util.Base64
import javax.crypto.Cipher

object Encrypt {

  def file(algorithm: String)(file: File, key: Key): Array[Byte] = {
    val cipher = Cipher.getInstance(algorithm)
    val size = file.length().toInt
    val content = new Array[Byte](size)
    val in = new FileInputStream(file)


    try {
      in.read(content)
      cipher.init(Cipher.ENCRYPT_MODE, key)
      cipher.doFinal(content)
    } finally {
      in.close()
    }
  }

  def wrap(algorithm: String, pubKey: PublicKey, encode: Array[Byte] => String)(key: Key): String = {
    val cipher = Cipher.getInstance(algorithm)
    cipher.init(Cipher.WRAP_MODE, pubKey)
    encode(cipher.wrap(key))
  }

  def apply[T](algorithm: String, transform: Array[Byte] => T)(data: Array[Byte], key: Key): T = {
    val cipher = Cipher.getInstance(algorithm)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    transform(cipher.doFinal(data))
  }

}

object Decrypt {

  def apply(raw: Array[Byte], algorithm: String, key: Key) = {
    val cipher = Cipher.getInstance(algorithm)
    cipher.init(Cipher.DECRYPT_MODE, key)
    cipher.doFinal(raw)
  }

  def apply(file: File, algorithm: String, key: Key) = {
    val cipher = Cipher.getInstance(algorithm)
    val size = file.length().toInt
    val content = new Array[Byte](size)
    val in = new FileInputStream(file)


    try {
      in.read(content)
      cipher.init(Cipher.DECRYPT_MODE, key)
      cipher.doFinal(content)
    } finally {
      in.close()
    }
  }

  def unwrap(privateKey: => PrivateKey, algorithm: String, decode: String => Array[Byte])(secret: String): Key = {
    val key = decode(secret)
    val cipher = Cipher.getInstance(algorithm)
    cipher.init(Cipher.UNWRAP_MODE, privateKey)
    cipher.unwrap(key, "AES", Cipher.SECRET_KEY)
  }

  def decrypt[T](decode: String => Array[Byte], transform: Array[Byte] => T, algorithm: String)(text: String, key: Key) = {

    transform(Decrypt(decode(text), algorithm, key))
  }

  def decrypt0[T](transform: Array[Byte] => T, algorithm: String)(raw: Array[Byte], key: Key) = {
    transform(Decrypt(raw, algorithm, key))
  }

}


object Base64Encode {

  def apply(raw: Array[Byte]): String = {
    new String(Base64.getEncoder.encode(raw))
  }

  def apply(text: String): String = apply(text.getBytes())
}

object Base64Decode {

  def apply(raw: Array[Byte]) = Base64.getDecoder.decode(raw)

  def apply(text: String): Array[Byte] = apply(text.getBytes())
}

object Hex{
  def apply(data: Array[Byte]): String = data.map{ b => Integer.toHexString(0xFF & b)}.mkString
}

abstract class Checksum{

  val EOF = -1

  def algorithm: String

  def apply(in: InputStream): String = {
    val digest = MessageDigest.getInstance(algorithm)
    val buf = new Array[Byte](256)
    var read = in.read(buf)
    while(read != EOF){
      digest.update(buf, 0, read)
      read = in.read(buf)
    }
    Hex(digest.digest())
  }

  def apply(data: Array[Byte]): String = apply(new ByteArrayInputStream(data))

  def apply(text: String): String = apply(text.getBytes())

  def apply[T](t: T)(implicit transform: T => Array[Byte]): String = apply(transform(t))
}

object MD5 extends Checksum{
  def algorithm: String = "MD5"
}

object MD2 extends Checksum{
  def algorithm: String = "MD2"
}

object SHA1 extends Checksum{
  def algorithm: String = "SHA1"
}