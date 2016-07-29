package com.biosimilarity.evaluator.spray

import java.io.InputStream
import java.security.{KeyStore, SecureRandom}
import javax.net.ssl.{KeyManagerFactory, SSLContext, TrustManagerFactory}

import com.biosimilarity.evaluator.distribution.EvalConfConfig
import spray.io.{SSLContextProvider, ServerSSLEngineProvider}

object SSLConfiguration {

  private def resourceStream(resourceName: String): InputStream = {
    val is: InputStream = getClass.getClassLoader.getResourceAsStream(resourceName)
    require(is.ne(null), s"Resource $resourceName not found")
    is
  }

  private def sslContext: SSLContext = {
    val keystore: String                         = "keystore.jks"
    val storepass: String                        = EvalConfConfig.read("storepass")
    val keypass: String                          = EvalConfConfig.read("keypass")
    val keyStore: KeyStore                       = KeyStore.getInstance("jks")
    val keyManagerFactory: KeyManagerFactory     = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    val trustManagerFactory: TrustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    val context: SSLContext                      = SSLContext.getInstance("TLS")
    keyStore.load(resourceStream(keystore), storepass.toCharArray)
    keyManagerFactory.init(keyStore, keypass.toCharArray)
    trustManagerFactory.init(keyStore)
    context.init(keyManagerFactory.getKeyManagers, trustManagerFactory.getTrustManagers, new SecureRandom)
    context
  }

  def sslEngineProvider: ServerSSLEngineProvider = ServerSSLEngineProvider(identity)(SSLContextProvider.forContext(sslContext))
}
