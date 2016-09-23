package com.cryptoutility.protocol


import java.security.{KeyPairGenerator, KeyFactory}
import java.util.UUID


import com.cryptoutility.protocol.Events._
import org.scalatest.{MustMatchers, WordSpec, Spec}

/**
  * Created by jay on 21/09/2016.
  */
class EventSerializerSpec extends WordSpec with MustMatchers{

  def generateKey = {
    KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic
  }

  "Initialised event serializer" should {
    "serialize and deserialize event" in {
      val expected = Initialized(isNew = false, UserInfo("James", "Carl", "james@example.com", generateKey, Some(UUID.randomUUID().toString)))
      val serialized = EventSerializer.serialize(expected)
      val deserialized = EventSerializer.deserialize(serialized)

      deserialized mustBe expected
    }
  }

}
