package com.biosimilarity.evaluator.spray.util

import org.scalatest.{Matchers, WordSpec}
import spray.testkit.ScalatestRouteTest

class HttpsDirectivesSpec extends WordSpec with HttpsDirectives with ScalatestRouteTest with Matchers {

  import com.biosimilarity.evaluator.distribution.EvalConfConfig
  import com.biosimilarity.evaluator.spray.util.HttpsDirectives.StrictTransportSecurity
  import spray.http.{HttpHeaders, StatusCodes, Uri}
  import spray.routing.Directives._
  import spray.routing.Route

  val httpUri: Uri  = Uri("http://alpha.synereo.com/api").withPort(EvalConfConfig.serverPort)
  val httpsUri: Uri = httpUri.withScheme("https").withPort(EvalConfConfig.serverSSLPort)

  "The requireHttps directive" should {

    val route: Route = requireHttps(complete(StatusCodes.OK))

    "allow https requests and responses should have a 'StrictTransportSecurity' header" in {
      Get(httpsUri) ~> route ~> check {
        status === StatusCodes.OK
        header(StrictTransportSecurity.name) should equal(Some(StrictTransportSecurity))
      }
    }

    """|allow terminated https requests containing a 'X-Forwarded-Proto' header
       |and response should contain a 'StrictTransportSecurity' header""".stripMargin in {
      Get(httpUri) ~> addHeader(HttpHeaders.RawHeader("X-Forwarded-Proto", "https")) ~> route ~> check {
        status === StatusCodes.OK
        header(StrictTransportSecurity.name) should equal(Some(StrictTransportSecurity))
      }
    }

    "redirect plain http requests to the corresponding https URI" in {
      Get(httpUri) ~> route ~> check {

        status === StatusCodes.MovedPermanently

        header[HttpHeaders.Location].map { (l: HttpHeaders.Location) =>
          Uri(l.value)
        } should equal(Some(httpsUri))

        header(StrictTransportSecurity.name) should equal(Some(StrictTransportSecurity))
      }
    }

    "redirect terminated http requests to the corresponding https URI" in {
      Get(httpUri) ~> addHeader(HttpHeaders.RawHeader("X-Forwarded-Proto", "http")) ~> route ~> check {

        status === StatusCodes.MovedPermanently

        header[HttpHeaders.Location].map { (l: HttpHeaders.Location) =>
          Uri(l.value)
        } should equal(Some(httpsUri))

        header(StrictTransportSecurity.name) should equal(Some(StrictTransportSecurity))
      }
    }
  }

  "The enforceHttpsIf directive" should {

    "enforce https when its argument is true" in {

      val route: Route = requireHttpsIf(true)(complete(StatusCodes.OK))

      Get(httpsUri) ~> route ~> check {
        status === StatusCodes.OK
        header(StrictTransportSecurity.name) should equal(Some(StrictTransportSecurity))
      }

      Get(httpUri) ~> route ~> check {

        status === StatusCodes.MovedPermanently

        header[HttpHeaders.Location].map { (l: HttpHeaders.Location) =>
          Uri(l.value)
        } should equal(Some(httpsUri))

        header(StrictTransportSecurity.name) should equal(Some(StrictTransportSecurity))
      }
    }

    "not enforce https when its arguments is false " in {

      val route: Route = requireHttpsIf(false)(complete(StatusCodes.OK))

      Get(httpsUri) ~> route ~> check {
        status === StatusCodes.OK
        header(StrictTransportSecurity.name) should equal(None)
      }

      Get(httpUri) ~> route ~> check {
        status === StatusCodes.OK
        header(StrictTransportSecurity.name) should equal(None)
      }
    }
  }
}
