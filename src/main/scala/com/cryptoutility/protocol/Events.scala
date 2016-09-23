package com.cryptoutility.protocol

import java.security.PublicKey

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


  case class UserInfo(fname: String, lname: String, email: String, key: PublicKey, clientId: Option[String] = None)


  case class Initialized(isNew: Boolean, user: UserInfo) extends Event
  case class UserCreated(user: UserInfo) extends Event

  sealed trait StreamEvent extends Event{
    def chunck: Array[Byte]

    def size: Int
  }

  case class StreamStarted(chunck: Array[Byte] = Array(), size: Int = 0) extends StreamEvent
  case class StreamPart(chunck: Array[Byte],  size: Int) extends StreamEvent
  case class StreamEnded(chunck: Array[Byte] = Array(), size: Int = 0) extends StreamEvent



  def id(event: Event): Int = event match {
    case e: Initialized => InitializedId
    case e: UserCreated => UserCreatedId
    case e: StreamStarted => StreamStartedId
    case e: StreamPart =>  StreamPartId
    case e: StreamEnded => StreamEndedId
  }

}
