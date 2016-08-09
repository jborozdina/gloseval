
import com.biosimilarity.evaluator.spray.EvaluatorService
import org.specs2.mutable.Specification
import spray.http._
import spray.testkit.Specs2RouteTest
import com.github.simplyscala.{MongoEmbedDatabase, MongodProps}
import org.bouncycastle.crypto.agreement.srp.{SRP6Client, SRP6StandardGroups, SRP6VerifierGenerator}
import org.bouncycastle.crypto.digests.SHA512Digest
import org.json4s._
import org.json4s.native.JsonMethods._

import scala.util.Try

object AuthenticationTestData {
  import com.biosimilarity.evaluator.spray.srp.ConversionUtils._

  val email = "testonly@test.com"
  val password = "qwerty12345"
  val srpClient = new SRP6Client()

  val createUserStep1RequestBody = s"""{"msgType":"createUserStep1Request","content":{"email":"$email"}}"""
  val confirmEmailTokenRequestBody = """{"msgType":"confirmEmailToken","content":{"token":"b08353e9"}}"""

  def getVerifier(salt: String) = {
    val verifierGenerator = new SRP6VerifierGenerator()
    verifierGenerator.init(SRP6StandardGroups.rfc5054_1024, new SHA512Digest())
    toHex(verifierGenerator.generateVerifier(salt.getBytes, email.getBytes, password.getBytes))
  }
  def getA(salt: String) = {
    srpClient.init(SRP6StandardGroups.rfc5054_1024,  new SHA512Digest(), getSecureRandom)
    toHex(srpClient.generateClientCredentials(salt.getBytes, email.getBytes, password.getBytes))
  }

  def getCreateUserStep2RequestBody(salt: String): String =
    s"""{"msgType":"createUserStep2Request","content":{"email":"$email","salt": "$salt","verifier":"${getVerifier(salt)}","jsonBlob":{"name":"test"}}}"""

  def getInitializeSessionStep1RequestBody(salt: String): String =
    s"""{"msgType":"initializeSessionStep1Request","content":{"agentURI":"agent://email/$email?A=${getA(salt)}"}}"""

  def getInitializeSessionStep2RequestBody(bVal: String): String = {
    srpClient.calculateSecret(fromHex(bVal))
    s"""{"msgType":"initializeSessionStep2Request","content":{"agentURI":"agent://email/$email?M=${toHex(srpClient.calculateClientEvidenceMessage())}"}}"""
  }
}

abstract class SpecificationBase extends Specification with MongoEmbedDatabase{
  sequential

  var mongoProps: MongodProps = null

  step{
    println("========================= Start Authentication Test ========================")
    mongoProps = mongoStart(27017)
  }

  include(spec)

  step{
    mongoStop(mongoProps)
    println("=========================== End Authentication Test =========================")
  }

  def spec: Specification
}

class AuthenticationTest extends SpecificationBase
  with Specs2RouteTest with EvaluatorService {

  implicit val formats = DefaultFormats

  var salt = ""
  var B = ""

  def actorRefFactory = system

  def spec = new Specification {
    import AuthenticationTestData._

    "EvaluationService" should {

      "return random salt on creation user, step 1" in {
        Post("/api", HttpEntity(MediaTypes.`application/json`, createUserStep1RequestBody)) ~> myRoute ~>
          check {
            val rsp = responseAs[String]
            rsp must contain("salt")

            val json = parse(rsp)
            val optSalt = Try((json \ "content"  \ "salt").extract[String]).toOption
            optSalt must not be None

            salt = optSalt.getOrElse("")
            salt must not be ""
          }
      }

      "respond with CreateUserWaiting on creation user, step 2" in {
        Post("/api", HttpEntity(MediaTypes.`application/json`, getCreateUserStep2RequestBody(salt))) ~> myRoute ~>
          check {
            val rsp = responseAs[String]
            rsp must contain("createUserWaiting")
          }
      }

      "generate agentURI on email token confirmation" in {
        Post("/api", HttpEntity(MediaTypes.`application/json`, confirmEmailTokenRequestBody)) ~> myRoute ~>
          check {
            val rsp = responseAs[String]
            val json = parse(rsp)
            val msgType = (json \ "msgType").extract[String]
            msgType must be equalTo "createUserStep2Response"

            val agentURI = (json \ "content" \ "agentURI").extract[String]
            agentURI must contain("agent://cap/")
          }
      }

      "respond with B parameter and stored salt on initializing new session, step 1" in {
        Post("/api", HttpEntity(MediaTypes.`application/json`, getInitializeSessionStep1RequestBody(salt))) ~> myRoute ~>
          check {
            val rsp = responseAs[String]
            val json = parse(rsp)
            val msgType = (json \ "msgType").extract[String]
            msgType must be equalTo "initializeSessionStep1Response"

            val s = (json \ "content" \ "s").extract[String]
            s must be equalTo salt

            B = (json \ "content" \ "B").extract[String]
            B must not be ""
          }
      }

      "respond with M2 parameter on initializing new session, step 2" in {
        Post("/api", HttpEntity(MediaTypes.`application/json`, getInitializeSessionStep2RequestBody(B))) ~> myRoute ~>
          check {
            val rsp = responseAs[String]
            val json = parse(rsp)
            val msgType = (json \ "msgType").extract[String]
            msgType must be equalTo "initializeSessionResponse"

            val m2 = (json \ "content" \ "M2").extract[String]
            m2 must not be ""
          }
      }
    }
  }
}