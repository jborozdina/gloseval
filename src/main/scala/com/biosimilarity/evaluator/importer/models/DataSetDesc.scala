package com.biosimilarity.evaluator.importer.models

import org.json4s._
import org.json4s.JsonDSL._
import org.json4s.jackson.JsonMethods._
import org.json4s.jackson.Serialization.write


/**
 * Describes a LivelyGig dataset.
 * @param agents
 * @param labels
 * @param cnxns
 */
case class DataSetDesc(
  agents: List[AgentDesc],
  labels: Option[List[SystemLabelDesc]],
  cnxns: Option[List[ConnectionDesc]],
  posts: Option[List[PostDesc]]
) {

  /**
   * Serializes to JSON.
   * @return JSON String.
   */
  implicit val formats = DefaultFormats
  def toJson = write(this)  
}

object DataSetDesc {

  implicit val formats = DefaultFormats

  /**
   * Parses an object from JSON.
   * @param json
   * @return
   */
  def fromJson(json: String) = parse(json).extract[DataSetDesc]

}

trait Process[T]
case class Zero[T]() extends Process[T]
case class InputGuarded[T](u : Name[T], v : Name[T], p : Process[T]) extends Process[T]
case class Output[T](u : Name[T], p : Process[T]) extends Process[T]
case class Par[T](l : Process[T], r : Process[T]) extends Process[T]
case class Deref[T](u : Name[T]) extends Process[T]

trait Name[U]
case class Refer[U](p : Process[U]) extends Name[U]

trait ReflectiveProcess
case class Reflect( p : Process[Name[ReflectiveProcess]] ) extends ReflectiveProcess


