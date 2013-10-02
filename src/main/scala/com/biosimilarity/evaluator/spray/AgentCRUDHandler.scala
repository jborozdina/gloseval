// -*- mode: Scala;-*- 
// Filename:    AgentCRUDHandler.scala 
// Authors:     lgm                                                    
// Creation:    Tue Oct  1 15:44:37 2013 
// Copyright:   Not supplied 
// Description: 
// ------------------------------------------------------------------------

package com.biosimilarity.evaluator.spray

import com.protegra_ati.agentservices.store._

import com.biosimilarity.evaluator.distribution._
import com.biosimilarity.evaluator.msgs._
import com.biosimilarity.evaluator.msgs.agent.crud._
import com.biosimilarity.lift.model.store._
import com.biosimilarity.lift.lib._

import akka.actor._
import spray.routing._
import directives.CompletionMagnet
import spray.http._
import spray.http.StatusCodes._
import MediaTypes._

import spray.httpx.encoding._

import org.json4s._
import org.json4s.native.JsonMethods._
import org.json4s.JsonDSL._

import scala.concurrent.duration._
import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.continuations._ 
import scala.collection.mutable.HashMap

import com.typesafe.config._

import javax.crypto._
import javax.crypto.spec.SecretKeySpec
import java.security._


import java.util.Date
import java.util.UUID

import java.net.URI

trait AgentCRUDHandler {
  self : EvaluationCommsService =>
 
  import DSLCommLink.mTT
  import ConcreteHL._

  //## Methods on Sessions
  //### Ping and pong
  def handlesessionPing(
    msg : sessionPing
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesessionPing with msg : " + msg
    )
  }
  def handlesessionPong(
    msg : sessionPong
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesessionPong with msg : " + msg
    )
  }

  //## Methods on Agents
  //### createAgent
  def handlecreateAgentRequest(
    key : String,
    msg : createAgentRequest
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlecreateAgentRequest with msg : " + msg
    )
  }
  //    - `authType == "password"` (case-insensitive)
  def handlecreateAgentError(
    key : String,
    msg : createAgentError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlecreateAgentError with msg : " + msg
    )
  }
  //    - returned synchronously
  def handlecreateAgentResponse(
    key : String,
    msg : createAgentResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlecreateAgentResponse with msg : " + msg
    )
  }
  //    - returned synchronously
  
  //### initializeSession
  def handleinitializeSessionRequest(
    key : String,
    msg : initializeSessionRequest
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleinitializeSessionRequest with msg : " + msg
    )
  }
  def handleinitializeSessionError(
    key : String,
    msg : initializeSessionError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleinitializeSessionError with msg : " + msg
    )
  }
  //    - returned synchronously
  def handleinitializeSessionResponse(
    key : String,
    msg : initializeSessionResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleinitializeSessionResponse with msg : " + msg
    )
  }
  //    - returned synchronously
  
  //### External identities
  //#### addAgentExternalIdentity
  def handleaddAgentExternalIdentityRequest[ID](
    key : String,
    msg : addAgentExternalIdentityRequest[ID]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  //    - `ID(idType: IDType, idValue: String)`
  //        - `IDType = Email`
  //    - We only support adding one identity per message because of need for confirmation
  def handleaddAgentExternalIdentityError(
    key : String,
    msg : addAgentExternalIdentityError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAgentExternalIdentityError with msg : " + msg
    )
  }
  def handleaddAgentExternalIdentityWaiting(
    key : String,
    msg : addAgentExternalIdentityWaiting
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAgentExternalIdentityWaiting with msg : " + msg
    )
  }
  def handleaddAgentExternalIdentityToken(
    key : String,
    msg : addAgentExternalIdentityToken
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAgentExternalIdentityToken with msg : " + msg
    )
  }
  def handleaddAgentExternalIdentityResponse(
    key : String,
    msg : addAgentExternalIdentityResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAgentExternalIdentityResponse with msg : " + msg
    )
  }
  
  //#### removeAgentExternalIdentities
  def handleremoveAgentExternalIdentitiesRequest[ID](
    key : String,
    msg : removeAgentExternalIdentitiesRequest[ID]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handleremoveAgentExternalIdentitiesError(
    key : String,
    msg : removeAgentExternalIdentitiesError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAgentExternalIdentitiesError with msg : "
  + msg
    )
  }
  def handleremoveAgentExternalIdentitiesResponse(
    key : String,
    msg : removeAgentExternalIdentitiesResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAgentExternalIdentitiesResponse with msg : " + msg
    )
  }
  
  //#### getAgentExternalIdentities
  def handlegetAgentExternalIdentitiesRequest[IDType](
    key : String,
    msg : getAgentExternalIdentitiesRequest[IDType]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  //    - One value of `IDType` is `ANY`
  def handlegetAgentExternalIdentitiesError(
    key : String,
    msg : getAgentExternalIdentitiesError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetAgentExternalIdentitiesError with msg : " + msg
    )
  }
  def handlegetAgentExternalIdentitiesResponse[ID](
    key : String,
    msg : getAgentExternalIdentitiesResponse[ID]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }

  var _aliasStorageLocation : Option[CnxnCtxtLabel[String,String,String]] = None
  def aliasStorageLocation() : CnxnCtxtLabel[String,String,String] = {
    _aliasStorageLocation match {
      case Some( asl ) => asl
      case None => {
        fromTermString(
          "aliasList( true )"
        ).getOrElse(
          throw new Exception( "Couldn't parse label: " + "aliasList( true )" )
        )          
      }
    }
  }  

  def agentFromSession(
    sessionURI: URI
  ) : URI = {
    new URI(
      "agentURI",
      sessionURI.getUserInfo(),
      sessionURI.getAuthority(),
      sessionURI.getPort(),
      sessionURI.getPath(),
      sessionURI.getQuery(),
      sessionURI.getFragment()
    )    
  }
  def identityAliasFromAgent(
    agentURI : URI
  ) : PortableAgentCnxn = {
    PortableAgentCnxn(agentURI, "identity", agentURI)
  }

  //### Aliases
  //#### addAgentAliases
  def handleaddAgentAliasesRequest(
    key : String,
    msg : addAgentAliasesRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleaddAgentAliasesRequest with msg : " + msg
    )
    val (erql, erspl) = agentMgr().makePolarizedPair()
    val aliasStorageCnxn =
      identityAliasFromAgent( agentFromSession( msg.sessionURI ) )
    val onGet : Option[mTT.Resource] => Unit = 
      ( optRsrc : Option[mTT.Resource] ) => {
        optRsrc match {
          case None => {
            // Nothing to be done
            BasicLogService.tweet("handleaddAgentAliasesRequest | onGet: got None")
          }
          case Some( mTT.RBoundHM( Some( mTT.Ground( v ) ), _ ) ) => {
            BasicLogService.tweet("handleaddAgentAliasesRequest | onGet: got " + v )
            val onPut : Option[mTT.Resource] => Unit =
              ( optRsrc : Option[mTT.Resource] ) => {
                BasicLogService.tweet("handleaddAgentAliasesRequest | onGet | onPut")
                CompletionMapper.complete(
                  key, 
                  compact(
                    render(
                      ( "msgType" -> "addAgentAliasesResponse" ) ~ ( "content" -> ( "sessionURI" -> msg.sessionURI.toString ) )
                    )
                  )
                )
              }
            v match {              
              case PostedExpr( previousAliasList : List[String] ) => {              
                val newAliasList = previousAliasList ++ msg.aliases
                BasicLogService.tweet("handleaddAgentAliasesRequest | onGet | onPut | updating aliasList with " + newAliasList )
                agentMgr().put[List[String]]( erql, erql )(
                  aliasStorageLocation, List( aliasStorageCnxn ), newAliasList, onPut
                )
              }
              case Bottom => {
                agentMgr().put[List[String]]( erql, erql )(
                  aliasStorageLocation, List( aliasStorageCnxn ), msg.aliases, onPut
                )
              }
            }
          }
          case wonky => {
            CompletionMapper.complete(key, compact(render(
              ("msgType" -> "addAgentAliasesError") ~
              ("content" -> ("reason" -> "Got wonky response: " + wonky.toString))
            )))
          }
        }
      }
    
    agentMgr().get( erql, erql )( aliasStorageLocation, List( aliasStorageCnxn ), onGet )
  }
  //    - `Alias = String`
  def handleaddAgentAliasesError(
    key : String,
    msg : addAgentAliasesError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAgentAliasesError with msg : " + msg
    )
  }
  def handleaddAgentAliasesResponse(
    key : String,
    msg : addAgentAliasesResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAgentAliasesResponse with msg : " + msg
    )
  }
  
  //#### removeAgentAliases
  def handleremoveAgentAliasesRequest(
    key : String,
    msg : removeAgentAliasesRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handleremoveAgentAliasesError(
    key : String,
    msg : removeAgentAliasesError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAgentAliasesError with msg : " + msg
    )
  }
  def handleremoveAgentAliasesResponse(
    key : String,
    msg : removeAgentAliasesResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAgentAliasesResponse with msg : " + msg
    )
  }
  
  //#### getAgentAliases
  def handlegetAgentAliasesRequest(
    key : String,
    msg : getAgentAliasesRequest
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetAgentAliasesRequest with msg : " + msg
    )
  }
  def handlegetAgentAliasesError(
    key : String,
    msg : getAgentAliasesError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetAgentAliasesError with msg : " + msg
    )
  }
  def handlegetAgentAliasesResponse(
    key : String,
    msg : getAgentAliasesResponse
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  
  //#### getDefaultAlias
  def handlegetDefaultAliasRequest(
    key : String,
    msg : getDefaultAliasRequest
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetDefaultAliasRequest with msg : " + msg
    )
  }
  def handlegetDefaultAliasError(
    key : String,
    msg : getDefaultAliasError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetDefaultAliasError with msg : " + msg
    )
  }
  def handlegetDefaultAliasResponse(
    key : String,
    msg : getDefaultAliasResponse
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  
  //#### setDefaultAlias
  def handlesetDefaultAliasRequest(
    key : String,
    msg : setDefaultAliasRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handlesetDefaultAliasError(
    key : String,
    msg : setDefaultAliasError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesetDefaultAliasError with msg : " + msg
    )
  }
  def handlesetDefaultAliasResponse(
    key : String,
    msg : setDefaultAliasResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesetDefaultAliasResponse with msg : " + msg
    )
  }
  
  //## Methods on Aliases
  //### External identities
  //#### addAliasExternalIdentities
  def handleaddAliasExternalIdentitiesRequest[ID](
    key : String,
    msg : addAliasExternalIdentitiesRequest[ID]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  //    - Only ids already on the agent are allowed
  def handleaddAliasExternalIdentitiesError(
    key : String,
    msg : addAliasExternalIdentitiesError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAliasExternalIdentitiesError with msg : " + msg
    )
  }
  def handleaddAliasExternalIdentitiesResponse(
    key : String,
    msg : addAliasExternalIdentitiesResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAliasExternalIdentitiesResponse with msg : "
  + msg
    )
  }
  
  //#### removeAliasExternalIdentities
  def handleremoveAliasExternalIdentitiesRequest[ID](
    key : String,
    msg : removeAliasExternalIdentitiesRequest[ID]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handleremoveAliasExternalIdentitiesError(
    key : String,
    msg : removeAliasExternalIdentitiesError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAliasExternalIdentitiesError with msg : "
  + msg
    )
  }
  def handleremoveAliasExternalIdentitiesResponse(
    key : String,
    msg : removeAliasExternalIdentitiesResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAliasExternalIdentitiesResponse with msg : " + msg
    )
  }
  
  //#### getAliasExternalIdentities
  def handlegetAliasExternalIdentitiesRequest[IDType](
    key : String,
    msg : getAliasExternalIdentitiesRequest[IDType]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  //    - One value of `IDType` is `ANY`
  def handlegetAliasExternalIdentitiesError(
    key : String,
    msg : getAliasExternalIdentitiesError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetAliasExternalIdentitiesError with msg : " + msg
    )
  }
  def handlegetAliasExternalIdentitiesResponse[IDType](
    key : String,
    msg : getAliasExternalIdentitiesResponse[IDType]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  
  //#### setAliasDefaultExternalIdentity
  def handlesetAliasDefaultExternalIdentityRequest[ID](
    key : String,
    msg : setAliasDefaultExternalIdentityRequest[ID]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handlesetAliasDefaultExternalIdentityError(
    key : String,
    msg : setAliasDefaultExternalIdentityError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesetAliasDefaultExternalIdentityError with msg : " + msg
    )
  }
  def handlesetAliasDefaultExternalIdentityResponse(
    key : String,
    msg : setAliasDefaultExternalIdentityResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesetAliasDefaultExternalIdentityResponse with msg : " + msg
    )
  }
  
  //### Connections
  //#### addAliasConnections
  def handleaddAliasConnectionsRequest[Cnxn](
    key : String,
    msg : addAliasConnectionsRequest[Cnxn]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  //    - `Cnxn = (URI, FlatTerm, URI)`
  def handleaddAliasConnectionsError(
    key : String,
    msg : addAliasConnectionsError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAliasConnectionsError with msg : " + msg
    )
  }
  def handleaddAliasConnectionsResponse(
    key : String,
    msg : addAliasConnectionsResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAliasConnectionsResponse with msg : " + msg
    )
  }
  
  //#### removeAliasConnections
  def handleremoveAliasConnectionsRequest[Cnxn](
    key : String,
    msg : removeAliasConnectionsRequest[Cnxn]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handleremoveAliasConnectionsError(
    key : String,
    msg : removeAliasConnectionsError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAliasConnectionsError with msg : " + msg
    )
  }
  def handleremoveAliasConnectionsResponse(
    key : String,
    msg : removeAliasConnectionsResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAliasConnectionsResponse with msg : " + msg
    )
  }
  
  //#### getAliasConnections
  def handlegetAliasConnectionsRequest(
    key : String,
    msg : getAliasConnectionsRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handlegetAliasConnectionsError(
    key : String,
    msg : getAliasConnectionsError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetAliasConnectionsError with msg : " + msg
    )
  }
  def handlegetAliasConnectionsResponse[Cnxn](
    key : String,
    msg : getAliasConnectionsResponse[Cnxn]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  
  //#### setAliasDefaultConnection
  def handlesetAliasDefaultConnectionRequest[Cnxn](
    key : String,
    msg : setAliasDefaultConnectionRequest[Cnxn]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handlesetAliasDefaultConnectionError(
    key : String,
    msg : setAliasDefaultConnectionError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesetAliasDefaultConnectionError with msg : " + msg
    )
  }
  def handlesetAliasDefaultConnectionResponse(
    key : String,
    msg : setAliasDefaultConnectionResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesetAliasDefaultConnectionResponse with msg : " + msg
    )
  }
  
  //### Labels
  //#### addAliasLabels
  def handleaddAliasLabelsRequest(
    key : String,
    msg : addAliasLabelsRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  //    - `Label = String`
  def handleaddAliasLabelsError(
    key : String,
    msg : addAliasLabelsError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAliasLabelsError with msg : " + msg
    )
  }
  def handleaddAliasLabelsResponse(
    key : String,
    msg : addAliasLabelsResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleaddAliasLabelsResponse with msg : " + msg
    )
  }
  
  //#### removeAliasLabels
  def handleremoveAliasLabelsRequest(
    key : String,
    msg : removeAliasLabelsRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handleremoveAliasLabelsError(
    key : String,
    msg : removeAliasLabelsError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAliasLabelsError with msg : " + msg
    )
  }
  def handleremoveAliasLabelsResponse(
    key : String,
    msg : removeAliasLabelsResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleremoveAliasLabelsResponse with msg : " + msg
    )
  }
  
  //#### getAliasLabels
  def handlegetAliasLabelsRequest(
    key : String,
    msg : getAliasLabelsRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handlegetAliasLabelsError(
    key : String,
    msg : getAliasLabelsError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetAliasLabelsError with msg : " + msg
    )
  }
  def handlegetAliasLabelsResponse(
    key : String,
    msg : getAliasLabelsResponse
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  
  //#### setAliasDefaultLabel
  def handlesetAliasDefaultLabelRequest(
    key : String,
    msg : setAliasDefaultLabelRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handlesetAliasDefaultLabelError(
    key : String,
    msg : setAliasDefaultLabelError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesetAliasDefaultLabelError with msg : " + msg
    )
  }
  def handlesetAliasDefaultLabelResponse(
    key : String,
    msg : setAliasDefaultLabelResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlesetAliasDefaultLabelResponse with msg : " + msg
    )
  }
  
  //#### getAliasDefaultLabel
  def handlegetAliasDefaultLabelRequest(
    key : String,
    msg : getAliasDefaultLabelRequest
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  def handlegetAliasDefaultLabelError(
    key : String,
    msg : getAliasDefaultLabelError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handlegetAliasDefaultLabelError with msg : " + msg
    )
  }
  def handlegetAliasDefaultLabelResponse(
    key : String,
    msg : getAliasDefaultLabelResponse
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  
  //### DSL
  //#### evalSubscribe
  def handleevalSubscribeRequest[GloSExpr](
    key : String,
    msg : evalSubscribeRequest[GloSExpr]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  //    - `GlosExpr =`
  //        - `InsertContent(Labels: List[Label], cnxns: List[Cnxn], value: Value)`
  //            - `Value = String`
  //        - `FeedExpr(Labels: List[Label], cnxns: List[Cnxn])`
  //        - `ScoreExpr(Labels: List[Label], cnxns: List[Cnxn], staff: Staff`
  //            - `Staff =`
  //                - `List[Cnxn]`
  //                - `List[Label]`
  def handleevalSubscribeError(
    key : String,
    msg : evalSubscribeError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleevalSubscribeError with msg : " + msg
    )
  }
  def handleevalSubscribeResponse[Value](
    key : String,
    msg : evalSubscribeResponse[Value]
  ) : Unit = {
    BasicLogService.tweet(
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
  //- Can we know when we are done to send back an `evalSubscribeComplete`?
  
  //#### evalSubscribeCancel
  def handleevalSubscribeCancelRequest(
    key : String,
    msg : evalSubscribeCancelRequest
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleevalSubscribeCancelRequest with msg : " + msg
    )
  }
  def handleevalSubscribeCancelError(
    key : String,
    msg : evalSubscribeCancelError
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleevalSubscribeCancelError with msg : " + msg
    )
  }
  def handleevalSubscribeCancelResponse(
    key : String,
    msg : evalSubscribeCancelResponse
  ) : Unit = {
    BasicLogService.tweet( 
      "Entering: handleevalSubscribeCancelResponse with msg : " + msg
    )
  }
}