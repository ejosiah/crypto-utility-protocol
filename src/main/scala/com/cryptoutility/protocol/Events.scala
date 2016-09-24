package com.cryptoutility.protocol

import java.security.PublicKey
import java.util.UUID

import scala.language.postfixOps
import scala.language.implicitConversions

/**
  * packet format
  *   stream length               Event Id                  Event Body
  *  ----- ----- ----- -----    ----- ----- ----- -----    ----- ----- ----- -----
  *  |    |     |     |     | - |     |     |     |    | - |     |     |     |    ......
  *  ----- ----- ----- -----    ----- ----- ----- -----    ----- ----- ----- -----
  */

object Events {
  case class InvalidFormatException() extends Exception("Not an event stream")

  val InitializedId = 0
  val UserCreatedId = 1
  val StreamStartedId = 2
  val StreamPartId = 3
  val StreamEndedId = 4


  sealed trait Event{
  }


  case class UserInfo(fname: String, lname: String, email: String, key: PublicKey, clientId: String = UUID.randomUUID().toString)


  case class Initialized(isNew: Boolean, user: UserInfo) extends Event
  case class UserCreated(user: UserInfo) extends Event

  sealed trait StreamEvent extends Event{
    def chunk: Array[Byte]

    def size: Int
  }

  case class StreamStarted(chunk: Array[Byte] = Array(), size: Int = 0) extends StreamEvent
  case class StreamPart(chunk: Array[Byte], size: Int) extends StreamEvent
  case class StreamEnded(chunk: Array[Byte] = Array(), size: Int = 0) extends StreamEvent



  def id(event: Event): Int = event match {
    case e: Initialized => InitializedId
    case e: UserCreated => UserCreatedId
    case e: StreamStarted => StreamStartedId
    case e: StreamPart =>  StreamPartId
    case e: StreamEnded => StreamEndedId
  }

}
