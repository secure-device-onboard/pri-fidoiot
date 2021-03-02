// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fido.iot.sample;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Optional;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.fido.iot.protocol.Composite;
import org.fido.iot.protocol.Const;
import org.fido.iot.protocol.DispatchResult;
import org.fido.iot.protocol.MessageDispatcher;

/**
 * Represents a WebClient for dispatching HTTP messages.
 */
public class WebClient implements Runnable {

  private static final String SSL_MODE = "fido.ssl.mode";
  private final MessageDispatcher dispatcher;
  private HttpClient httpClient;
  private String baseUri;
  private String sslAlgorithm = "TLS";
  private SSLParameters sslParameters;
  private DispatchResult helloMessage;

  /**
   * Constructs a WebClient instance.
   *
   * @param baseUri      The base url of the protocol.
   * @param helloMessage The Dispatch result of the first hello message.
   * @param dispatcher   A message dispatcher.
   */
  public WebClient(String baseUri, DispatchResult helloMessage, MessageDispatcher dispatcher) {
    this.dispatcher = dispatcher;
    this.baseUri = baseUri;
    this.helloMessage = helloMessage;
  }

  /**
   * Sets the SSL algorithm to use.
   *
   * @param sslAlgorithm A SSL algorithm name.
   */
  public void setSslAlgorithm(String sslAlgorithm) {
    this.sslAlgorithm = sslAlgorithm;
  }

  /**
   * Sets the SSLParamters to use.
   *
   * @param sslParameters The SSLParameters.
   */
  public void setSslParameters(SSLParameters sslParameters) {
    this.sslParameters = sslParameters;
  }

  protected SSLParameters getSslParematers() {
    if (sslParameters == null) {
      return new SSLParameters();
    }
    return sslParameters;
  }

  /**
   * Get SSLContext for making request.
   */
  public SSLContext getSslContext() throws KeyManagementException, NoSuchAlgorithmException {
    try {

      String sslMode = System.getProperty(SSL_MODE, "test");

      if (sslMode.toLowerCase().equals("test")) {

        // Validity of certificate is not checked.
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
              public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
              }

              public void checkClientTrusted(
                  java.security.cert.X509Certificate[] certs, String authType) {
              }

              public void checkServerTrusted(
                  java.security.cert.X509Certificate[] certs, String authType) {
              }

            }
        };

        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        return sslContext;
      } else if (sslMode.toLowerCase().equals("prod")) {
        //load values from catalina propeties
        String keyStoreFile = "ocs-keystore.p12";
        String keyStorePwd = "RT2y!KlP5";
        String keyStoreType = "PKCS12";

        String trustStoreFile = "mfg-trustore";
        String trustStorePwd = "intel123";
        String trustStoreType = "PKCS12";

        final KeyStore identityKeyStore = KeyStore.getInstance(keyStoreType);
        final File keystoreFile = new File(keyStoreFile);
        final FileInputStream identityKeyStoreFile = new FileInputStream(keystoreFile);
        identityKeyStore.load(identityKeyStoreFile, keyStorePwd.toCharArray());

        final KeyManagerFactory kmf =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(identityKeyStore, keyStorePwd.toCharArray());
        final KeyManager[] km = kmf.getKeyManagers();

        final KeyStore trustKeyStore = KeyStore.getInstance(trustStoreType);
        final File truststoreFile = new File(trustStoreFile);
        final FileInputStream trustKeyStoreFile = new FileInputStream(truststoreFile);
        trustKeyStore.load(trustKeyStoreFile, trustStorePwd.toCharArray());

        final TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustKeyStore);
        final TrustManager[] tm = tmf.getTrustManagers();

        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tm, SecureRandom.getInstanceStrong());
        return sslContext;


      } else {
        throw new RuntimeException("Invalid SSL mode. Use TEST or PROD.");
      }
      //SSLContext sslContext = SSLContext.getDefault();
      //SSLContext sc = SSLContext.getInstance("SSL");
      //SSLContext sslContext = SSLContext.getDefault();
      //sc.init(null, trustAllCerts, new SecureRandom());

      //     return sc;
    } catch (Exception e) {
      System.out.println("Error occurred while creating ssl context. " + e.getMessage());
      return null;
    }
  }

  protected HttpClient getHttpsClient() {
    if (httpClient == null) {
      try {
        httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .sslContext(getSslContext())
            .sslParameters(getSslParematers())
            .build();
      } catch (NoSuchAlgorithmException | KeyManagementException e) {
        throw new RuntimeException(e);
      }
    }
    return httpClient;
  }

  protected HttpClient getHttpClient() {
    if (httpClient == null) {
      try {
        httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .sslContext(SSLContext.getInstance(sslAlgorithm))
            .sslParameters(getSslParematers())
            .build();
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    }
    return httpClient;
  }

  private String getMessagePath(int protocolVersion, int msgId) {
    String leadPath = "/";
    if (baseUri.endsWith("/")) {
      leadPath = "";
    }
    return baseUri + leadPath + "fdo/" + Integer.toString(protocolVersion)
        + "/msg/" + Integer.toString(msgId);
  }

  private DispatchResult sendMessage(Composite message) throws IOException, InterruptedException {
    String url = getMessagePath(message.getAsNumber(Const.SM_PROTOCOL_VERSION).intValue(),
        message.getAsNumber(Const.SM_MSG_ID).intValue());

    if (url.startsWith("https")) {
      getHttpsClient();
    } else {
      getHttpClient();
    }

    HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
        .uri(URI.create(url));

    byte[] body = message.getAsComposite(Const.SM_BODY).toBytes();
    reqBuilder.setHeader("Content-Type", Const.HTTP_APPLICATION_CBOR);

    Composite info = message.getAsComposite(Const.SM_PROTOCOL_INFO);
    if (info.containsKey(Const.PI_TOKEN)) {
      reqBuilder.setHeader(Const.HTTP_AUTHORIZATION,
          Const.HTTP_BEARER + " " + info.getAsString(Const.PI_TOKEN));
    }

    reqBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(body));

    HttpResponse<byte[]> hr = httpClient
        .send(reqBuilder.build(), HttpResponse.BodyHandlers.ofByteArray());

    if (hr.statusCode() == Const.HTTP_OK) {

      Composite authInfo = Composite.newMap();
      Optional<String> msgType = hr.headers().firstValue(Const.HTTP_MESSAGE_TYPE);
      Optional<String> authToken = hr.headers().firstValue(Const.HTTP_AUTHORIZATION);
      if (authToken.isPresent()) {
        String[] authArray = authToken.get().split("\\s+");
        if (authArray.length > 1) {
          if (authArray[0].compareToIgnoreCase(Const.HTTP_BEARER) == 0) {
            authInfo.set(Const.PI_TOKEN, authArray[1]);
          }
        }



      }
      Composite reply = Composite.newArray()
          .set(Const.SM_LENGTH, Const.DEFAULT)
          .set(Const.SM_MSG_ID, Integer.valueOf(msgType.get()))
          .set(Const.SM_PROTOCOL_VERSION,
              message.getAsNumber(Const.SM_PROTOCOL_VERSION))
          .set(Const.SM_PROTOCOL_INFO, authInfo)
          .set(Const.SM_BODY, Composite.fromObject(hr.body()));

      return new DispatchResult(reply, false);
    }

    throw new RuntimeException("http status: " + hr.statusCode());

  }

  @Override
  public void run() {

    try {
      DispatchResult dr = helloMessage;
      while (!dr.isDone()) {
        dr = sendMessage(dr.getReply());
        dr = dispatcher.dispatch(dr.getReply());
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    } catch (InterruptedException e) {
      throw new RuntimeException(e);
    }
  }
}
