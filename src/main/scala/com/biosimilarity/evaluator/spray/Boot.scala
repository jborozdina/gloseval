package com.biosimilarity.evaluator.spray

import akka.actor.{ActorSystem, Props}
import akka.io.IO
import com.biosimilarity.evaluator.distribution.EvalConfConfig
import com.biosimilarity.evaluator.omniRPC.OmniClient
import com.typesafe.config.{Config, ConfigFactory}
import spray.can.Http
import spray.can.server.ServerSettings

object Boot extends App with Serializable {

  //TODO: Remove sleep below once race condition is fixed
  // @@GS - is it fixed??
  Thread.sleep(3000)

  com.biosimilarity.evaluator.distribution.bfactory.BFactoryMapInitializer.makeMap()

  @transient
  implicit val system = ActorSystem("evaluator-system")

  @transient
  val service = system.actorOf(Props[EvaluatorServiceActor], "evaluator-service")

  @transient
  val config: Config = ConfigFactory.load()

  @transient
  val nonSSLSettings: ServerSettings = ServerSettings(config).copy(sslEncryption = false)

  IO(Http) ! Http.Bind(listener = service, interface = "0.0.0.0", port = EvalConfConfig.serverPort, settings = Some(nonSSLSettings))

  IO(Http) ! Http.Bind(listener = service, interface = "0.0.0.0", port = EvalConfConfig.serverSSLPort)(SSLConfiguration.sslEngineProvider)

  if (EvalConfConfig.isOmniRequired() && !OmniClient.canConnect()) throw new Exception("Unable to connect to OmniCore")
}
