package com.biosimilarity.evaluator.importer.dtos

import org.json4s._

case class ApiRequest(msgType: String, content: RequestContent)

object Api {

  // helpers
  case class EvalSubscribeContent(cnxns: List[Connection], label: String, value: String, uid: String)
  case class EvalSubscribeExpression(msgType: String, content: EvalSubscribeContent)


  trait RequestContent {}
  // actual API
  case class Request(msgType: String, content: RequestContent)

  case class CreateUserRequest(email: String,password: String,jsonBlob: JObject) extends RequestContent
  case class GetAgentRequest(email: String,password: String) extends RequestContent
  case class UpdateUserRequest(sessionURI: String,jsonBlob: JObject) extends RequestContent
  case class StartSessionRecording(sessionURI: String) extends RequestContent
  case class StopSessionRecording(sessionURI: String) extends RequestContent
  case class SessionPing(sessionURI: String) extends RequestContent
  case class InitializeSessionRequest(agentURI: String) extends RequestContent
  case class AddAliasLabelsRequest(sessionURI: String, alias: String, labels: List[String]) extends RequestContent
  case class EstablishConnectionRequest(sessionURI: String, aURI: String, bURI: String, label: String) extends RequestContent
  case class EvalSubscribeRequest(sessionURI: String, expression: EvalSubscribeExpression) extends RequestContent
  case class ResetDatabaseRequest(sessionURI: String, mongodbPath: String) extends RequestContent
  case class GetAmpWalletAddress(sessionURI: String) extends RequestContent
  case class SetAmpWalletAddress(sessionURI: String, address: String) extends RequestContent

  def toReq[T <: RequestContent](cont: T) : Request = {
    val nm = cont.getClass.getSimpleName()
    val tnm = Character.toLowerCase(nm.charAt(0)) + nm.substring(1)
    Api.Request(tnm, cont)
  }

}