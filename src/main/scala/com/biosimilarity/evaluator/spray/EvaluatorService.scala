package com.biosimilarity.evaluator.spray

import akka.actor._
import com.biosimilarity.lift.lib._
import com.biosimilarity.evaluator.distribution._
import com.biosimilarity.evaluator.spray.util.HttpsDirectives
import spray.routing._
import java.util.UUID

import org.json4s.JsonDSL._
import org.json4s._
import org.json4s.native.JsonMethods._
import spray.http._
import spray.httpx.encoding._

import scala.collection.mutable.HashMap
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._


/**
 * CometMessage used when some data needs to be sent to a client
 * with the given id
 */
case class CometMessage(data: String)
  extends Serializable

/**
 * Poll used when a client wants to register/long-poll with the
 * server
 */
case class SessionPing(reqCtx: RequestContext) extends Serializable

/**
 * PollTimeout sent when a long-poll requests times out
 */
case class PollTimeout() extends Serializable
case class SetSessionId(id : String) extends Serializable
case class KeepAlive() extends Serializable
case class RunFunction(fn : JObject => Unit, content : JObject) extends Serializable


/**
 * ClientGc sent to deregister a client when it hasnt pinged in a long time
 */
case class CloseSession() extends Serializable

class CometActor extends Actor with Serializable {
  val gcTime = EvalConfConfig.readInt("sessionTimeoutMinutes") minutes // if client doesnt poll within this time, its garbage collected
  val clientTimeout = EvalConfConfig.readInt("pongTimeoutSeconds") seconds // ping requests are ponged after this much time, clients need to re-ping after this
  @transient
  var aliveTimer = context.system.scheduler.scheduleOnce(gcTime, self, CloseSession())
  @transient
  var optReq : Option[(RequestContext, Cancellable)] = None
  @transient
  var msgs = List[String]() // sets of async return messages
  var sessionId : Option[String] = None

  override def postStop() = {
    sessionId = None
  }

  def resetAliveTimer() = {
    aliveTimer.cancel()
    aliveTimer = context.system.scheduler.scheduleOnce(gcTime, self, CloseSession())
  }

  def receive = {
    case SetSessionId(id) => {
      sessionId = Some(id)
      resetAliveTimer()
    }
    case KeepAlive() => {
      resetAliveTimer()
    }
    case SessionPing(reqCtx) => {
      for (ssn <- sessionId) {
        resetAliveTimer()
        for ((_, tmr) <- optReq) tmr.cancel()
        msgs match {
          case Nil => {
            optReq = Some(reqCtx, context.system.scheduler.scheduleOnce(clientTimeout, self, PollTimeout()))
          }
          case _ => {
            reqCtx.complete(HttpResponse(entity = "[" + msgs.reverse.mkString(",") + "]"))
            msgs = Nil
          }
        }
      }
    }
    case PollTimeout() => {
      for (ssn <- sessionId) {
        optReq match {
          case Some((req, _)) => {
            req.complete(HttpResponse(entity = compact(render(
              List(("msgType" -> "sessionPong") ~ ("content" -> ("sessionURI" -> ssn)))))))
            optReq = None
          }
          case None => ()
        }
      }
    }
    case CloseSession() => {
      context.stop(self)
      for (ssn <- sessionId) CometActorMapper.map -= ssn
    }
    case RunFunction(fn,content) => {
      fn(content)
    }
    case CometMessage(data) => {
      resetAliveTimer()
      msgs = data :: msgs
      optReq match {
        case None => () //println("CometMessage optReqCtx miss: id = " + sessionId)
        case Some((reqCtx,tmr)) => {
          reqCtx.complete(HttpResponse(entity = "[" + msgs.reverse.mkString(",") + "]"))
          optReq = None
          msgs = Nil
          tmr.cancel()
        }
      }
    }
  }
}

// we don't implement our route structure directly in the service actor because
// we want to be able to test it independently, without having to spin up an actor
class EvaluatorServiceActor extends Actor
  with EvaluatorService
  with Serializable {
  import EvalHandlerService._

  // create well-known node user
  createNodeUser(NodeUser.email, NodeUser.password, NodeUser.jsonBlob)

  // this actor only runs our route, but you could add
  // other things here, like request stream processing
  // or timeout handling
  def receive = runRoute(myRoute)

  def actorRefFactory = context

}

case class InitializeSessionException(agentURI: String, message: String) extends Exception with Serializable

trait EvaluatorService extends HttpService with HttpsDirectives with CORSSupport {

  import EvalHandlerService._

  def createNewSession(json: JObject, key: String): Unit = {
    initializeSessionRequest(json, key, ssn => {
      val actor = actorRefFactory.actorOf(Props[CometActor])
      actor ! SetSessionId(ssn)
      CometActorMapper.map += (ssn -> actor)
    })
  }

  @transient
  val syncMethods = HashMap[String, (JObject, String) => Unit](
    // Old stuff
    ("createUserRequest", createUserRequest),
    ("confirmEmailToken", confirmEmailToken),
    // New API
    ("createAgentRequest", createAgentRequest),
    ("initializeSessionRequest", createNewSession),
    ("getAgentRequest", getAgentRequest)
  )

  @transient
  val asyncMethods = HashMap[String, JObject => Unit](
    // Old stuff
    ("closeSessionRequest", closeSessionRequest),
    ("updateUserRequest", updateUserRequest),
    // Agents
    ("addAgentExternalIdentityRequest", addAgentExternalIdentityRequest),
    ("addAgentExternalIdentityToken", addAgentExternalIdentityToken),
    ("removeAgentExternalIdentitiesRequest", removeAgentExternalIdentitiesRequest),
    ("getAgentExternalIdentitiesRequest", getAgentExternalIdentitiesRequest),
    ("addAgentAliasesRequest", addAgentAliasesRequest),
    ("removeAgentAliasesRequest", removeAgentAliasesRequest),
    ("getAgentAliasesRequest", getAgentAliasesRequest),
    ("getDefaultAliasRequest", getDefaultAliasRequest),
    ("setDefaultAliasRequest", setDefaultAliasRequest),
    // Aliases
    ("addAliasExternalIdentitiesRequest", addAliasExternalIdentitiesRequest),
    ("removeAliasExternalIdentitiesRequest", removeAliasExternalIdentitiesRequest),
    ("getAliasExternalIdentitiesRequest", getAliasExternalIdentitiesRequest),
    ("setAliasDefaultExternalIdentityRequest", setAliasDefaultExternalIdentityRequest),
    // Connections
    ("removeAliasConnectionsRequest", removeAliasConnectionsRequest),
    ("getAliasConnectionsRequest", getAliasConnectionsRequest),
    ("getConnectionProfiles", getConnectionProfiles),
    // Alias Labels
    ("addAliasLabelsRequest", addAliasLabelsRequest),
    ("updateAliasLabelsRequest", updateAliasLabelsRequest),
    ("getAliasLabelsRequest", getAliasLabelsRequest),
    ("setAliasDefaultLabelRequest", setAliasDefaultLabelRequest),
    ("getAliasDefaultLabelRequest", getAliasDefaultLabelRequest),
    // System Labels
    //("addSystemLabelsRequest", addSystemLabelsRequest),
    // DSL
    ("evalSubscribeRequest", evalSubscribeRequest),
    ("evalSubscribeCancelRequest", evalSubscribeCancelRequest),
    // Introduction Protocol
    ("beginIntroductionRequest", beginIntroductionRequest),
    ("introductionConfirmationRequest", introductionConfirmationRequest),
    ("establishConnectionRequest", establishConnectionRequest),
    // Database dump/restore
    ("backupRequest", backupRequest),
    ("restoreRequest", restoreRequest),
    ("resetDatabaseRequest", resetDatabaseRequest),
    // Verifier protocol
    ("initiateClaim", initiateClaim),
    // omni
    ("omniGetBalance", omniGetBalance),
    ("omniTransfer", omniTransfer),
    ("getAmpWalletAddress", omniGetAmpWalletAddress),
    ("setAmpWalletAddress", omniSetAmpWalletAddress)

  )

  @transient
  val myRoute =
    requireHttps {
      cors {
        path("api") {
          post {
            decodeRequest(NoEncoding) {
              entity(as[String]) { jsonStr =>
                (ctx) => {
                  try {
                    //BasicLogService.tweet("json: " + jsonStr)
                    val json = parse(jsonStr)
                    val msgType = (json \ "msgType").extract[String]
                    val content = (json \ "content").extract[JObject]
                    syncMethods.get(msgType) match {
                      case Some(fn) =>
                        val key = UUID.randomUUID.toString
                        CompletionMapper.map += (key -> ctx)
                        fn(content, key)
                      case None => (content \ "sessionURI").extract[Option[String]] match {
                        case Some(sessionURI) =>
                          CometActorMapper.map.get(sessionURI) match {
                            case None => ctx.complete(StatusCodes.Forbidden)
                            case Some(cometActor) => msgType match {
                              case "sessionPing" => cometActor ! SessionPing(ctx)
                              case _ =>
                                cometActor ! KeepAlive()
                                asyncMethods.get(msgType) match {
                                  case Some(fn) =>
                                    cometActor ! RunFunction(fn, content) // run function in actor thread
                                    ctx.complete(StatusCodes.OK)
                                  case _ =>
                                    ctx.complete(HttpResponse(500, "Unknown message type: " + msgType + "\n"))
                                }
                            }
                          }
                      }
                    }
                  }
                  catch {
                    case th: Throwable =>
                      val writer: java.io.StringWriter = new java.io.StringWriter()
                      val printWriter: java.io.PrintWriter = new java.io.PrintWriter(writer)
                      th.printStackTrace(printWriter)
                      printWriter.flush()

                      val stackTrace: String = writer.toString()
                      //println( "Malformed request: \n" + stackTrace )
                      BasicLogService.tweet("Malformed request: \n" + stackTrace)
                      ctx.complete(HttpResponse(500, "Malformed request: \n" + stackTrace))
                  }
                }
              }
            }
          }
        } ~
          pathPrefix("agentui") {
            getFromDirectory("./agentui")
          }

      }
    }
}

/*
        path("admin/connectServers") {
          // allow administrators to make
          // sure servers are connected
          // BUGBUG : lgm -- make this secure!!!
          get {
            parameters('whoAmI) {
              (whoAmI: String) =>
                {
                  //             println(
                  //               (
                  //                 " >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "
                  //                 + "in admin/connectServers2 "
                  //                 + " >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "
                  //               )
                  //             )
                  BasicLogService.tweet(
                    (
                      " >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "
                      + "in admin/connectServers2 "
                      + " >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "))

                  connectServers("evaluator-service", UUID.randomUUID)

                  (cometActor ! SessionPing("", _))
                }
            }
          }
        } ~
        pathPrefix("splicious/btc") {
          get {
            parameters('btcToken) {
              (btcToken: String) =>
                {
                  BasicLogService.tweet(
                    (
                      " >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "
                      + "in splicious/btc "
                      + " >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "))

                  handleBTCResponse(btcToken)

                  (cometActor ! SessionPing("", _))

                }
            }
          }
        }
  */
