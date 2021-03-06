package com.cryptoutility.protocol

import java.security.PublicKey
import java.util.UUID
import scala.language.postfixOps
import scala.language.implicitConversions
import scala.util.control.NonFatal
import scala.util.{Success, Failure, Try}

/**
  * packet format
  *   stream length               Event Id                  Event Body
  *  ----- ----- ----- -----    ----- ----- ----- -----    ----- ----- ----- -----
  *  |    |     |     |     | - |     |     |     |    | - |     |     |     |    ......
  *  ----- ----- ----- -----    ----- ----- ----- -----    ----- ----- ----- -----
  */

object Events {
  case class InvalidFormatException() extends Exception("Not an event stream")

  sealed abstract class Done

  case object Done extends Done


  val InitializedId = 0
  val UserCreatedId = 1
  val StreamStartedId = 2
  val StreamPartId = 3
  val StreamEndedId = 4
  val StreamingResultId = 5


  sealed trait Event extends Ordered[Event]{
    override def compare(that: Event): Int = id(this).compareTo(id(this))
  }


  case class UserInfo(fname: String, lname: String, email: String, key: PublicKey, clientId: String = UUID.randomUUID().toString)


  case class Initialized(isNew: Boolean, user: UserInfo) extends Event
  case class UserCreated(user: UserInfo) extends Event

  sealed trait StreamEvent extends Event

  case class StreamStarted(filename: String, contentType: String, from: String, secret: String) extends StreamEvent

  case class StreamPart(seqId: Long, chunk: Array[Byte]) extends StreamEvent{
    override def compare(that: Event): Int = {
      val i = super.compare(that)
      if(i == 0 && that.isInstanceOf[StreamPart]){
        seqId.compare(that.asInstanceOf[StreamPart].seqId)
      }else i
    }
  }

  case class StreamEnded(size: Long, secret: String, mac: String) extends StreamEvent

  case class StreamingResult(count: Long, status: Try[Done]) extends StreamEvent{

    def wasSuccessful = status.isSuccess

    def getError = status match {
      case Failure(NonFatal(e)) => e
      case Success(_) => throw new UnsupportedOperationException("streaming was successful")
    }
  }

  def id(event: Event): Int = event match {
    case e: Initialized => InitializedId
    case e: UserCreated => UserCreatedId
    case e: StreamStarted => StreamStartedId
    case e: StreamPart =>  StreamPartId
    case e: StreamEnded => StreamEndedId
    case e: StreamingResult => StreamingResultId
  }

}
