// -*- mode: Scala;-*- 
// Filename:    BTCHandler.scala 
// Authors:     lgm                                                    
// Creation:    Thu Apr 10 15:49:40 2014 
// Copyright:   Not supplied 
// Description: 
// ------------------------------------------------------------------------

package com.biosimilarity.evaluator.spray

import com.biosimilarity.evaluator.distribution.portable.btc.v0_1._

import com.protegra_ati.agentservices.store._
import com.protegra_ati.agentservices.protocols.msgs._

import com.biosimilarity.evaluator.distribution._
import com.biosimilarity.evaluator.msgs._
import com.biosimilarity.evaluator.msgs.agent.crud._
import com.biosimilarity.evaluator.prolog.PrologDSL._
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
import scala.collection.mutable.MapProxy
import scala.collection.mutable.HashMap

import com.typesafe.config._

import javax.crypto._
import javax.crypto.spec.SecretKeySpec
import java.security._


import java.util.Date
import java.util.UUID

import java.net.URI
import java.net.URL

trait BTCPaymentStatus
case object BTCPaymentPending extends BTCPaymentStatus
case object BTCPaymentComplete extends BTCPaymentStatus
case object BTCPaymentFailed extends BTCPaymentStatus

object BTCPaymentSessions extends MapProxy[String,BTCPaymentStatus] with Serializable {
  @transient
  override val self = new HashMap[String,BTCPaymentStatus]()
}

trait BTCHandlerSchema {
  self : EvaluationCommsService with DownStreamHttpCommsT =>
 
  import DSLCommLink.mTT
  import ConcreteHL._
}

trait BTCHandler extends BTCHandlerSchema with CapUtilities {
  self : EvaluationCommsService with DownStreamHttpCommsT =>
 
  import DSLCommLink.mTT
  import ConcreteHL._
  import BlockChainAPI._

  def btcReceivePaymentCallbackURL() : URL

  def dispatchRsp(
    optRsrc : Option[mTT.Resource],
    handleRsp : ConcreteHL.HLExpr => Unit
  ) : Unit = {      
    optRsrc match {
      case None => ();
      case Some(mTT.Ground( v )) => {
        handleRsp( v )
      }
      case Some(mTT.RBoundHM(Some(mTT.Ground( v )), _)) => {
        handleRsp( v )
      }
    }
  }
  
  def handleSupportRequest(
    msg : supportRequest
  ) : Unit = {
    // set up a handler for the callback on payment receipt
    BTCPaymentSessions += ( msg.sessionId -> BTCPaymentPending )

    val btcWalletQry =
      //fromTermString( s"""btc( walletAddress( Address ) )""" ).get    
      fromTermString(
        s"""btc( wallet( guid( _ ), address( _ ), link( _ ) ) )"""
      ).get

    val btcReceivingAddressQry =
      //fromTermString( s"""btc( walletAddress( Address ) )""" ).get    
      fromTermString(
        s"""btc( receivingAddress( sessionId( ${msg.sessionId} ) ) )"""
      ).get

    val btcOutGoingPaymentQry =
      //fromTermString( s"""btc( walletAddress( Address ) )""" ).get    
      fromTermString(
        s"""btc( payment( sessionId( ${msg.sessionId} ) ) )"""
      ).get
    
    def handleReceivingAddressRsp( guid : String )( v : ConcreteHL.HLExpr ) : Unit = {
      v match {
        case Bottom => {
          println(
            (
              "*********************************************************************************"
              + "\nwaiting for btc receiving address json data"
              + "\nmsg.to: " + msg.to
              + "\nbtcReceivingAddressQry: " + btcReceivingAddressQry
              + "\n*********************************************************************************"
            )
          )
          BasicLogService.tweet(
            (
              "*********************************************************************************"
              + "\nwaiting for btc receiving address json data"
              + "\nmsg.to: " + msg.to
              + "\nbtcReceivingAddressQry: " + btcReceivingAddressQry
              + "\n*********************************************************************************"
            )
          )          
        }
        case PostedExpr( (PostedExpr( receivingAddrRsp : ReceivingAddressResponse ), _, _, _ ) ) => {
          println(
            (
              "*********************************************************************************"
              + "\nreceived btc receiving address json data"
              + "\nmsg.to: " + msg.to
              + "\nbtcReceivingAddressQry: " + btcReceivingAddressQry
              + "\nbtcWalletAddress: " + receivingAddrRsp
              + "\n*********************************************************************************"
            )
          )
          BasicLogService.tweet(
            (
              "*********************************************************************************"
              + "\nreceived btc receiving address json data"
              + "\nmsg.to: " + msg.to
              + "\nbtcReceivingAddressQry: " + btcReceivingAddressQry
              + "\nbtcWalletAddress: " + receivingAddrRsp
              + "\n*********************************************************************************"
            )
          )

          // issue payment from the supporter
          val mopd =
            MakeOutgoingPaymentData(
              pw( msg.from.toString, "" ), // BUGBUG : lgm -- this
                                           // should be the email, or
                                           // we should store and
                                           // retrieve it
              receivingAddrRsp.input_address,
              msg.splix,
              "", // BUGBUG : lgm -- need to get this from store
              "a little support"
            )
          val mop =
            MakeOutgoingPayment(
              mopd,
              guid
            )

          ask(
            msg.from,
            btcOutGoingPaymentQry,
            mop,
            ( optRsrc : Option[mTT.Resource] ) => println( "blockchain response: " + optRsrc )
          )

          // wait for response and notify ui
        }
        case _ => {
          println(
            (
              "*********************************************************************************"
              + "\nunexpected btc json data format" + v
              + "\nmsg.to: " + msg.to
              + "\nbtcWalletQry: " + btcWalletQry
              + "\n*********************************************************************************"
            )
          )
          BasicLogService.tweet(
            (
              "*********************************************************************************"
              + "\nunexpected btc json data format" + v
              + "\nmsg.to: " + msg.to
              + "\nbtcWalletQry: " + btcWalletQry
              + "\n*********************************************************************************"
            )
          )
          throw new Exception( "unexpected btc json data format" + v )
        }
      }
    }

    def handleWalletRsp( v : ConcreteHL.HLExpr ) : Unit = {
      v match {
        case Bottom => {
          println(
            (
              "*********************************************************************************"
              + "\nwaiting for btc json data"
              + "\nmsg.to: " + msg.to
              + "\nbtcWalletQry: " + btcWalletQry
              + "\n*********************************************************************************"
            )
          )
          BasicLogService.tweet(
            (
              "*********************************************************************************"
              + "\nwaiting for btc json data"
              + "\nmsg.to: " + msg.to
              + "\nbtcWalletQry: " + btcWalletQry
              + "\n*********************************************************************************"
            )
          )          
        }
        case PostedExpr( (PostedExpr( cwrsp : CreateWalletResponse ), _, _, _ ) ) => {
          println(
            (
              "*********************************************************************************"
              + "\nreceived btc json data"
              + "\nmsg.to: " + msg.to
              + "\nbtcWalletQry: " + btcWalletQry
              + "\nCreateWalletResponse: " + cwrsp
              + "\n*********************************************************************************"
            )
          )
          BasicLogService.tweet(
            (
              "*********************************************************************************"
              + "\nreceived btc json data"
              + "\nmsg.to: " + msg.to
              + "\nbtcWalletQry: " + btcWalletQry
              + "\nCreateWalletResponse: " + cwrsp
              + "\n*********************************************************************************"
            )
          )

          // create a receiving address for the recipient    
          val crad =
            CreateReceivingAddressData(
              cwrsp.address,
              btcReceivePaymentCallbackURL().toString
            )
          val cra = CreateReceivingAddress( crad )

          val btcReceivingAddressQry =
            fromTermString( s"""btc( receivingAddress( Address ) )""" ).get

          ask(
            msg.to,
            btcReceivingAddressQry,
            cra,
            ( optRsrc : Option[mTT.Resource] ) => println( "blockchain response: " + optRsrc )
          )
    
          get(
            btcReceivingAddressQry,
            List( msg.to ), 
            ( optRsrc : Option[mTT.Resource] ) => {
              dispatchRsp( optRsrc, (handleReceivingAddressRsp( cwrsp.guid ) _) )
            }
          )
        }
        case _ => {
          println(
            (
              "*********************************************************************************"
              + "\nunexpected btc json data format" + v
              + "\nmsg.to: " + msg.to
              + "\nbtcWalletQry: " + btcWalletQry
              + "\n*********************************************************************************"
            )
          )
          BasicLogService.tweet(
            (
              "*********************************************************************************"
              + "\nunexpected btc json data format" + v
              + "\nmsg.to: " + msg.to
              + "\nbtcWalletQry: " + btcWalletQry
              + "\n*********************************************************************************"
            )
          )
          throw new Exception( "unexpected btc json data format" + v )
        }
      }
    }            

    read(
      btcWalletQry,
      List( msg.to ),
      ( optRsrc : Option[mTT.Resource] ) => {
        dispatchRsp( optRsrc, handleWalletRsp )
      }
    )
  }
  
  def handleReceivingAddressResponse(
    msg : receivingAddressResponse
  ) : Unit = {
  }

  def handlePaymentNotification(
    msg : receivingAddressResponse
  ) : Unit = {
  }
}
