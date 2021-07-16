// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fidoalliance.fdo.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import org.fidoalliance.fdo.protocol.DiffieHellman.KeyExchange;
import org.fidoalliance.fdo.protocol.epid.EpidMaterialService;
import org.fidoalliance.fdo.protocol.epid.EpidSignatureVerifier;
import org.fidoalliance.fdo.protocol.ondie.OnDieService;

/**
 * Cryptography Service.
 *
 * <p>Performs cryptographic operations a formats cryptographic data</p>
 */
public final class CryptoService {

  static final BouncyCastleProvider BCPROV = new BouncyCastleProvider();
  private SecureRandom secureRandom;
  private boolean epidTestMode = false;

  /**
   * Constructs a CryptoService from a list of algorithm names.
   *
   * @param algNames Random number generation algorithm names.
   */
  public CryptoService(String[] algNames) {

    SecureRandom rnd = null;
    if (algNames != null && algNames.length > 0) {
      for (String alg : algNames) {
        try {
          rnd = SecureRandom.getInstance(alg);
          break;
        } catch (NoSuchAlgorithmException e) {
          //suppress priority list
        }
      }
    }
    // no algorithm found in priority list
    if (rnd == null) {
      try {
        rnd = SecureRandom.getInstanceStrong();
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    }
    secureRandom = rnd;
  }

  /**
   * Constructs a CryptoService using default secure random number generator.
   */
  public CryptoService() {
    try {
      secureRandom = SecureRandom.getInstanceStrong();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Sets the epid test mode.
   *
   */
  public void setEpidTestMode() {
    this.epidTestMode = true;
  }

  /**
   * Gets the secure random number generator.
   *
   * @return The Random number generator being used by the service.
   */
  public SecureRandom getSecureRandom() {
    return secureRandom;
  }

  /**
   * Gets the security provider key factory algorithm from the fido spec key type.
   *
   * @param algId The spec key type.
   * @return The key factor algorithm.
   * @throws NoSuchAlgorithmException If the algorithm is not supported.
   */
  protected String getKeyFactoryAlgorithm(int algId) throws NoSuchAlgorithmException {
    switch (algId) {
      case Const.PK_SECP256R1:
      case Const.PK_SECP384R1:
      case Const.PK_ONDIE_ECDSA_384:
        return Const.EC_ALG_NAME;
      case Const.PK_RSA2048RESTR:
      case Const.PK_RSA3072:
        return Const.RSA_ALG_NAME;
      default:
        throw new NoSuchAlgorithmException();
    }
  }

  /**
   * get the MAC key given a secret.
   *
   * @param secret The secret.
   * @param algName The HMAC Algorithm.
   * @return The key based on the secret and HMAC algorithm.
   */
  protected SecretKey getHmacKey(byte[] secret, String algName) {
    return new SecretKeySpec(secret, algName);
  }

  protected KeyFactory getKeyFactoryInstance(String algName) throws NoSuchAlgorithmException {
    return KeyFactory.getInstance(algName);
  }

  protected Mac getMacInstance(String algName) throws NoSuchAlgorithmException {
    return Mac.getInstance(algName);
  }

  protected MessageDigest getDigestInstance(String algName) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance(algName);
  }

  protected Signature getSignatureInstance(String algName) throws NoSuchAlgorithmException {
    return Signature.getInstance(algName);
  }

  protected KeyAgreement getKeyAgreementInstance(String algName) throws NoSuchAlgorithmException {
    return KeyAgreement.getInstance(algName);
  }

  protected Cipher getCipherInstance(String algName)
      throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
    switch (algName) {
      case Const.AES128_CTR_HMAC256_ALG_NAME:
      case Const.AES256_CTR_HMAC384_ALG_NAME:
        return Cipher.getInstance("AES/CTR/NoPadding");
      case Const.AES128_CBC_HMAC256_ALG_NAME:
      case Const.AES256_CBC_HMAC384_ALG_NAME:
        return Cipher.getInstance("AES/CBC/PKCS7Padding", BCPROV);
      case Const.AES128_GCM_ALG_NAME:
      case Const.AES256_GCM_ALG_NAME:
        return Cipher.getInstance("AES/GCM/NoPadding");
      default:
        throw new CryptoServiceException(new NoSuchAlgorithmException());
    }
  }

  protected String getHashAlgorithm(int algId) throws NoSuchAlgorithmException {
    switch (algId) {
      case Const.SHA_256:
        return Const.SHA_256_ALG_NAME;
      case Const.SHA_384:
        return Const.SHA_384_ALG_NAME;
      case Const.SHA_512:
        return Const.SHA_512_ALG_NAME;
      case Const.HMAC_SHA_256:
      case Const.HMAC_SHA_256_KX:
        return Const.HMAC_256_ALG_NAME;
      case Const.HMAC_SHA_384:
      case Const.HMAC_SHA_384_KX:
        return Const.HMAC_384_ALG_NAME;
      case Const.HMAC_SHA_512_KX:
        return Const.HMAC_512_ALG_NAME;
      default:
        throw new NoSuchAlgorithmException();
    }
  }

  /**
   * Gets the Signature algorithm from COSE algorithm id.
   *
   * @param coseAlg The COSE algorithm Id.
   * @return The Signature algorithm represented by the COSE algorithm id.
   * @throws NoSuchAlgorithmException If the cose Algorithm is not supported.
   */
  public String getSignatureAlgorithm(int coseAlg) throws NoSuchAlgorithmException {
    switch (coseAlg) {
      case Const.COSE_ES256:
        return Const.ECDSA_256_ALG_NAME;
      case Const.COSE_ES384:
      case Const.COSE_ES384_ONDIE:
        return Const.ECDSA_384_ALG_NAME;
      case Const.COSE_RS384:
        return Const.RSA_384_ALG_NAME;
      case Const.COSE_RS256:
        return Const.RSA_256_ALG_NAME;
      default:
        throw new NoSuchAlgorithmException();
    }
  }

  /**
   * Gets the COSE algorithm id from a key.
   *
   * @param key A public or private key.
   * @return The COSE algorithm id.
   */
  public int getCoseAlgorithm(Key key) {
    if (key instanceof ECKey) {
      int bitLength = ((ECKey) key).getParams().getCurve().getField().getFieldSize();
      if (bitLength == Const.BIT_LEN_256) {
        return Const.COSE_ES256;
      } else if (bitLength == Const.BIT_LEN_384) {
        return Const.COSE_ES384;
      }
    } else if (key instanceof RSAKey) {
      int bitLength = ((RSAKey) key).getModulus().bitLength();
      if (Const.BIT_LEN_2K == bitLength) {
        return Const.COSE_RS256;
      } else if (Const.BIT_LEN_3K == bitLength) {
        return Const.COSE_RS384;
      }
    }
    throw new RuntimeException(new NoSuchAlgorithmException());
  }

  /**
   * Get the public key type id.
   *
   * @param key A public or private key.
   * @return The spec public key type.
   */
  public int getPublicKeyType(Key key) {
    if (key instanceof ECKey) {
      int bitLength = ((ECKey) key).getParams().getCurve().getField().getFieldSize();
      if (bitLength == Const.BIT_LEN_256) {
        return Const.PK_SECP256R1;
      }
      if (bitLength == Const.BIT_LEN_384) {
        return Const.PK_SECP384R1;
      }
    } else if (key instanceof RSAKey) {
      return Const.PK_RSA2048RESTR;
    }
    throw new RuntimeException(new NoSuchAlgorithmException());
  }

  /**
   * Gets SignInfo associated with the key.
   *
   * @param key A Public key
   * @return The signInfo
   */
  public Composite getSignInfo(Key key) {
    if (key instanceof ECKey) {
      int bitLength = ((ECKey) key).getParams().getCurve().getField().getFieldSize();
      if (bitLength == Const.BIT_LEN_256) {
        return Composite.newArray()
            .set(Const.SG_TYPE, Const.PK_SECP256R1)
            .set(Const.SG_INFO, Const.EMPTY_BYTE);
      }
      if (bitLength == Const.BIT_LEN_384) {
        return Composite.newArray()
            .set(Const.SG_TYPE, Const.PK_SECP384R1)
            .set(Const.SG_INFO, Const.EMPTY_BYTE);
      }
    } else if (key instanceof RSAKey) {
      int bitLength = ((RSAKey)key).getModulus().bitLength();
      if (Const.BIT_LEN_2K == bitLength) {
        return Composite.newArray()
            .set(Const.SG_TYPE, Const.PK_RSA2048RESTR)
            .set(Const.SG_INFO, Const.EMPTY_BYTE);
      } else if (Const.BIT_LEN_3K == bitLength) {
        return Composite.newArray()
            .set(Const.SG_TYPE, Const.PK_RSA3072)
            .set(Const.SG_INFO, Const.EMPTY_BYTE);
      }
    }
    throw new RuntimeException(new NoSuchAlgorithmException());
  }

  /**
   * Verify bytes are equal.
   *
   * @param nonce1 the first byte array to compare.
   * @param nonce2 the second byte array to compare.
   * @throws InvalidMessageException If nonce1 and nonce2 are not equal.
   */
  public void verifyBytes(byte[] nonce1, byte[] nonce2) {
    if (ByteBuffer.wrap(nonce1).compareTo(ByteBuffer.wrap(nonce2)) != 0) {
      throw new InvalidMessageException();
    }
  }

  /**
   * Verifies the hash of a payload.
   *
   * @param hashValue A composite representing a hash.
   * @param payload The payload to verify.
   */
  public void verifyHash(Composite hashValue, byte[] payload) {

    Composite hashResult = hash(hashValue.getAsNumber(Const.HASH_TYPE).intValue(), payload);
    ByteBuffer hash1 = hashValue.getAsByteBuffer(Const.HASH);
    ByteBuffer hash2 = hashResult.getAsByteBuffer(Const.HASH);

    if (hash1.compareTo(hash2) != 0) {
      throw new InvalidMessageException();
    }
  }

  /**
   * Determines if keys are equal.
   *
   * @param key1 The first key.
   * @param key2 The second key.
   * @return True if key1 equals key2, otherwise false.
   */
  public int compare(PublicKey key1, PublicKey key2) {

    if (key1 instanceof ECPublicKey && key1 instanceof ECPublicKey) {
      ECPublicKey ecc1 = (ECPublicKey) key1;
      ECPublicKey ecc2 = (ECPublicKey) key2;

      if (ecc1.getW().getAffineX().equals(ecc2.getW().getAffineX())
          && ecc1.getW().getAffineY().equals(ecc2.getW().getAffineY())) {
        return 0;
      }

    } else if (key1 instanceof RSAPublicKey && key2 instanceof RSAPublicKey) {
      RSAPublicKey rsa1 = (RSAPublicKey) key1;
      RSAPublicKey rsa2 = (RSAPublicKey) key2;

      if (rsa1.getModulus().equals(rsa2.getModulus())
          && rsa1.getPublicExponent().equals(rsa2.getPublicExponent())) {

        return 0;
      }
    }
    return -1;
  }

  /**
   * Gets the compatible encoding type for the key.
   *
   * @param key A public key.
   * @return The supported encoding type for the key.
   */
  public int getCompatibleEncoding(PublicKey key) {
    if (key instanceof ECPublicKey) {
      return Const.PK_ENC_COSEEC;
    } else if (key instanceof RSAPublicKey) {
      return Const.PK_ENC_X509;
    }
    throw new RuntimeException(new InvalidKeyException());
  }

  /**
   * Get the Hash type id compatible with a key.
   *
   * @param key A public key.
   * @return The hash id compatible with the key.
   */
  public int getCompatibleHashType(PublicKey key) {

    if (key instanceof ECPublicKey) {
      int bitLength = ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize();
      if (bitLength == Const.BIT_LEN_256) {
        return Const.SHA_256;
      }
      if (bitLength == Const.BIT_LEN_384) {
        return Const.SHA_384;
      }
    } else if (key instanceof RSAPublicKey) {
      int bitLength = ((RSAPublicKey) key).getModulus().bitLength();
      if (2 * 1024 == bitLength) {
        return Const.SHA_256;
      } else {
        return Const.SHA_384;
      }
    }
    throw new RuntimeException(new InvalidKeyException());
  }

  /**
   * Gets the Hash algorithm id.
   *
   * @param key A public key.
   * @return The supporting HMAC algorithm id for the given key.
   */
  public int getCompatibleHmacType(PublicKey key) {

    if (key instanceof ECPublicKey) {
      int bitLength = ((ECPublicKey) key).getParams().getCurve().getField().getFieldSize();
      if (bitLength == Const.BIT_LEN_256) {
        return Const.HMAC_SHA_256;
      }
      if (bitLength == Const.BIT_LEN_384) {
        return Const.HMAC_SHA_384;
      }
    } else if (key instanceof RSAPublicKey) {
      int bitLength = ((RSAPublicKey) key).getModulus().bitLength();
      if (2 * 1024 == bitLength) {
        return Const.HMAC_SHA_256;
      } else {
        return Const.HMAC_SHA_384;
      }
    }
    throw new CryptoServiceException(new NoSuchAlgorithmException());
  }

  /**
   * Returns actual signature.
   *
   * @param sigInfoA initial device based information
   * @return signature
   */
  public Composite getSigInfoB(Composite sigInfoA) {
    if (null != sigInfoA && sigInfoA.size() > 0
            && Arrays.asList(Const.SG_EPIDv10, Const.SG_EPIDv11)
            .contains(sigInfoA.getAsNumber(Const.FIRST_KEY).intValue())) {
      EpidMaterialService epidMaterialService = new EpidMaterialService();
      try {
        return epidMaterialService.getSigInfo(sigInfoA);
      } catch (IOException ioException) {
        throw new RuntimeException(ioException);
      }
    }
    return sigInfoA;
  }

  protected byte[] adjustBigBuffer(byte[] buffer, int byteLength) {
    final ByteBuffer result = ByteBuffer.allocate(byteLength);
    int skip = 0;
    //skip leading zero that BigInteger may add
    while ((buffer.length - skip) > byteLength) {
      skip++;
    }
    int pad = 0;
    // left pad with zero if not correct size
    while (buffer.length + pad < byteLength) {
      pad++;
      result.put((byte) 0);
    }
    result.put(buffer, skip, buffer.length - skip);
    result.flip();
    return Composite.unwrap(result);
  }

  /**
   * Encodes the public key.
   *
   * @param publicKey A public key.
   * @param encType A compatible encoding type.
   * @return The encode public key as a Composite.
   */
  public Composite encode(PublicKey publicKey, int encType) {
    final Composite pm = Composite.newArray();
    pm.set(Const.PK_ENC, encType);
    switch (encType) {

      case Const.PK_ENC_COSEEC: {

        final ECPublicKey ec = (ECPublicKey) publicKey;
        final byte[] x = ec.getW().getAffineX().toByteArray();
        final byte[] y = ec.getW().getAffineY().toByteArray();
        final int bitLength = ec.getParams().getCurve().getField().getFieldSize();
        final int byteLength = bitLength / Byte.SIZE;

        final ByteBuffer body = ByteBuffer.allocate(byteLength * 2);
        body.put(adjustBigBuffer(x, byteLength));
        body.put(adjustBigBuffer(y, byteLength));
        body.flip();

        if (bitLength == Const.BIT_LEN_256) {
          pm.set(Const.PK_TYPE, Const.PK_SECP256R1);
        } else if (bitLength == Const.BIT_LEN_384) {
          pm.set(Const.PK_TYPE, Const.PK_SECP384R1);
        } else {
          throw new CryptoServiceException(new InvalidKeyException());
        }
        pm.set(Const.PK_BODY, body);

      }
      break;
      case Const.PK_ENC_CRYPTO: {
        RSAPublicKey key = (RSAPublicKey) publicKey;
        final ByteBuffer mod = ByteBuffer.wrap(key.getModulus().toByteArray());
        final ByteBuffer exp = ByteBuffer.wrap(key.getPublicExponent().toByteArray());

        Composite pkbody = Composite.newArray()
                .set(Const.FIRST_KEY, mod)
                .set(Const.SECOND_KEY, exp);

        pm.set(Const.PK_BODY, pkbody);
        pm.set(Const.PK_TYPE, getPublicKeyType(publicKey));
      }
      break;
      case Const.PK_ENC_X509: {
        X509EncodedKeySpec x509 = new X509EncodedKeySpec(publicKey.getEncoded());
        pm.set(Const.PK_ENC, Const.PK_ENC_X509);
        pm.set(Const.PK_BODY, x509.getEncoded());
        pm.set(Const.PK_TYPE, getPublicKeyType(publicKey));
      }
        break;
      default:
        throw new CryptoServiceException(new NoSuchAlgorithmException());
    }
    return pm;
  }

  /**
   * Gets the public key represented from the Compiste.
   *
   * @param pub An Composite representing a public Key.
   * @return The Public key.
   */
  public PublicKey decode(Composite pub) {

    final int keyType = pub.getAsNumber(Const.PK_TYPE).intValue();
    final int keyEnc = pub.getAsNumber(Const.PK_ENC).intValue();

    KeyFactory factory;
    try {
      switch (keyEnc) {
        case Const.PK_ENC_CRYPTO:
          Composite cryptoBody = pub.getAsComposite(Const.PK_BODY);
          BigInteger mod = new BigInteger(1, cryptoBody.getAsBytes(Const.FIRST_KEY));
          BigInteger exp = new BigInteger(1, cryptoBody.getAsBytes(Const.SECOND_KEY));

          RSAPublicKeySpec rsaPkSpec = new RSAPublicKeySpec(mod, exp);
          factory = getKeyFactoryInstance(getKeyFactoryAlgorithm(keyType));
          return factory.generatePublic(rsaPkSpec);

        case Const.PK_ENC_X509:
          final byte[] x509body = pub.getAsBytes(Const.PK_BODY);
          final X509EncodedKeySpec rsaSpec = new X509EncodedKeySpec(x509body);
          factory = getKeyFactoryInstance(getKeyFactoryAlgorithm(keyType));

          return factory.generatePublic(rsaSpec);

        case Const.PK_ENC_COSEEC:
          final byte[] coseEecBody = pub.getAsBytes(Const.PK_BODY);
          final ByteBuffer buf509;
          if (keyType == Const.PK_SECP256R1) {
            buf509 = ByteBuffer.allocate(Const.X509_EC256_HEADER.length + coseEecBody.length);
            buf509.put(Const.X509_EC256_HEADER);
          } else if (keyType == Const.PK_SECP384R1) {
            buf509 = ByteBuffer.allocate(Const.X509_EC384_HEADER.length + coseEecBody.length);
            buf509.put(Const.X509_EC384_HEADER);
          } else {
            throw new NoSuchAlgorithmException();
          }
          buf509.put(coseEecBody);
          buf509.flip();

          factory = getKeyFactoryInstance(getKeyFactoryAlgorithm(keyType));
          final X509EncodedKeySpec escSpec = new X509EncodedKeySpec(Composite.unwrap(buf509));
          return factory.generatePublic(escSpec);

        default:
          throw new CryptoServiceException(new InvalidParameterException());
      }
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new CryptoServiceException(e);
    }
  }

  /**
   * Gets Secure Random bytes form the internal Random number generator.
   *
   * @param size The number of bytes to get.
   * @return Byte array containing the random bytes.
   */
  public byte[] getRandomBytes(int size) {
    final byte[] buffer = new byte[size];
    getSecureRandom().nextBytes(buffer);
    return buffer;
  }

  /**
   * Verifies MAROE Prefix.
   *
   * @param cose The COSE message
   */
  public void verifyMaroePrefix(Composite cose) {
    Composite uph = cose.getAsComposite(Const.COSE_SIGN1_UNPROTECTED);
    String maroePrefix = Composite.toString(uph.getAsBytes(Const.EAT_MAROE_PREFIX));
    boolean isMaroePrefixValid = false;
    for (final String maroePrefixItem : Const.MAROE_PREFIX_LIST) {
      if (maroePrefix.equals(maroePrefixItem)) {
        isMaroePrefixValid = true;
        break;
      }
    }
    if (!isMaroePrefixValid) {
      throw new RuntimeException("Invalid MAROE Prefix");
    }
  }

  /**
   * Verifies a COSE signature. Handles generic ECCDSA EPID and OnDie ECDSA signatures.
   *
   * @param verificationKey The verification key to use.
   * @param cose            The COSE message.
   * @param sigInfoA        The sigInfo object representing eA
   * @param onDieService    The onDie service.
   * @param onDieCertPath   The onDie cert path.
   * @return True if the signature matches otherwise false.
   */
  public boolean verify(PublicKey verificationKey,
                        Composite cose,
                        Composite sigInfoA,
                        OnDieService onDieService,
                        Composite onDieCertPath) {
    if (null != sigInfoA && sigInfoA.size() > 0 && Arrays.asList(Const.SG_EPIDv10, Const.SG_EPIDv11)
        .contains(sigInfoA.getAsNumber(Const.FIRST_KEY).intValue())) {
      // EPID verification
      verifyMaroePrefix(cose);
      EpidSignatureVerifier.Result verificationResult =
              EpidSignatureVerifier.verify(cose, sigInfoA);
      if (verificationResult == EpidSignatureVerifier.Result.VERIFIED) {
        return true;
      } else if (this.epidTestMode) {
        // in test mode ignore the validation of EPID signatures but
        // still perform the verification to check for non-signature issues
        if (verificationResult == EpidSignatureVerifier.Result.UNKNOWN_ERROR
                || verificationResult == EpidSignatureVerifier.Result.MALFORMED_REQUEST) {
          return false;
        }
        return true;
      }
      return false;
    }

    final byte[] protectedHeader;
    final Composite header1;
    final Object rawHeader = cose.get(Const.COSE_SIGN1_PROTECTED);
    if (rawHeader instanceof byte[]) {
      protectedHeader = cose.getAsBytes(Const.COSE_SIGN1_PROTECTED);
      header1 = Composite.fromObject(protectedHeader);
    } else {
      throw new UnsupportedOperationException("Illegal protected header encoding");
    }
    final int algId = header1.getAsNumber(Const.COSE_ALG).intValue();
    final ByteBuffer payload = cose.getAsByteBuffer(Const.COSE_SIGN1_PAYLOAD);
    final byte[] sig = cose.getAsBytes(Const.COSE_SIGN1_SIGNATURE);

    try {
      // OnDie ECDSA signature verification
      if (algId == Const.COSE_ES384_ONDIE) {
        if (onDieService == null) {
          throw new SignatureException("Internal error: onDieService not initialized.");
        }
        try {
          // if cert path is given then check revocations
          // else just check the signature
          if (onDieCertPath != null) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<Certificate> certPath = new ArrayList<>();
            for (int i = 0; i < onDieCertPath.size(); i++) {
              certPath.add(
                      cf.generateCertificate(
                              new ByteArrayInputStream((byte[]) onDieCertPath.get(i))));
            }
            return onDieService.validateSignature(certPath, payload.array(), sig);
          } else {
            return onDieService.validateSignature(verificationKey, payload.array(), sig);
          }
        } catch (CertificateException ex) {
          return false;
        }
      }

      // ECDSA verification
      final String algName = getSignatureAlgorithm(algId);
      final Signature signer = getSignatureInstance(algName);

      // Signature must be computed over a sig_structure:
      // Sig_structure = [
      //   context : "Signature" / "Signature1" / "CounterSignature",
      //   body_protected : empty_or_serialized_map,
      //   external_aad : bstr,
      //   payload : bstr
      // ]
      //
      // See the COSE RFC 8152 for details on this.

      Composite sigStruct = Composite.newArray()
          .set(Const.FIRST_KEY, "Signature1")
          .set(Const.SECOND_KEY, protectedHeader)
          .set(Const.THIRD_KEY, new byte[0])
          .set(Const.FOURTH_KEY, payload);

      byte [] derSig = sig;
      if (verificationKey instanceof ECKey) {
        // The encoded signature is fixed-width r|s concatenated, we must convert it to DER.
        int size = sig.length / 2;
        ASN1Integer r = new ASN1Integer(new BigInteger(1, sig, 0, size));
        ASN1Integer s = new ASN1Integer(new BigInteger(1, sig, size, size));
        DLSequence sequence = new DLSequence(new ASN1Encodable[]{r, s});
        ByteArrayOutputStream sigBytes = new ByteArrayOutputStream();
        ASN1OutputStream asn1out = ASN1OutputStream.create(sigBytes);
        asn1out.writeObject(sequence);
        byte [] b = sigBytes.toByteArray();
        derSig = Arrays.copyOf(b, b.length);
      }

      signer.initVerify(verificationKey);
      signer.update(sigStruct.toBytes());
      return signer.verify(derSig);

    } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IOException e) {
      throw new CryptoServiceException(e);
    }
  }

  /**
   * Verifies a certificate chain.
   *
   * @param chain A Composite array of certificate
   */
  public void verify(Composite chain) {

    final Set<TrustAnchor> anchors = new HashSet<>();

    try {
      final CertPath cp = getCertPath(chain);

      for (int i = 1; i < chain.size(); i++) {
        X509Certificate anchorCert = (X509Certificate) cp.getCertificates().get(i);
        anchors.add(new TrustAnchor(anchorCert, null));
      }

      final CertPathValidator validator =
            CertPathValidator.getInstance(getValidatorAlgorithm());

      final CertPathParameters params = getCertPathParameters(anchors);

      validator.validate(cp, params);
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
        | CertificateException | CertPathValidatorException e) {
      throw new CryptoServiceException(e);
    }
  }

  /**
   * Verifies certificate algorithm.
   *
   * @param algorithmName Public key algorithm
   */
  public void verifyAlgorithm(String algorithmName) throws InvalidOwnershipVoucherException {
    if (!(algorithmName.equals(Const.EC_ALG_NAME))) {
      throw new InvalidOwnershipVoucherException(
          "Wrong public key algorithm inside the device certificate - supported: ECDSA, received: "
              + algorithmName);
    }
  }

  /**
   * Verifies certificate public key curve.
   *
   * @param ecdsaCurveName ECDSA curve name
   */
  private void verifyCurveName(String ecdsaCurveName) throws InvalidOwnershipVoucherException {
    if (!(ecdsaCurveName.contains(Const.SECP256R1_CURVE_NAME)
        || ecdsaCurveName.contains(Const.PRIME256V1_CURVE_NAME)
        || ecdsaCurveName.contains(Const.SECP384R1_CURVE_NAME))) {
      throw new InvalidOwnershipVoucherException("Mismatch of ECDSA curve type.");
    }
  }

  /**
   * Verifies certificate public key size.
   *
   * @param pubKeySize Public key size
   */
  private void verifyKeySize(int pubKeySize) throws InvalidOwnershipVoucherException {
    if (pubKeySize != Const.BIT_LEN_256 && pubKeySize != Const.BIT_LEN_384) {
      throw new InvalidOwnershipVoucherException(
          "Wrong public key size. Received public key size: {}." + pubKeySize);
    }
  }

  /**
   * Verifies leaf certificate public key in ownership voucher.
   *
   * @param cert leaf certificate from ownership voucher
   */
  private void verifyLeafPubKeyData(X509Certificate cert) throws InvalidOwnershipVoucherException {
    String publicKeyAlgorithm = cert.getPublicKey().getAlgorithm();
    verifyAlgorithm(publicKeyAlgorithm);

    String ecdsaCurveName;
    ECParameterSpec p = ((ECPublicKey) cert.getPublicKey()).getParams();
    if (p instanceof ECNamedCurveSpec) {
      ECNamedCurveSpec ncs = (ECNamedCurveSpec)p;
      ecdsaCurveName = ncs.getName();
    } else {
      ecdsaCurveName = p.toString();
    }

    verifyCurveName(ecdsaCurveName);

    int pubKeySize =
        ((ECPublicKey) cert.getPublicKey()).getParams().getCurve().getField().getFieldSize();
    verifyKeySize(pubKeySize);
  }

  /**
   * Verifies leaf certificate in ownership voucher.
   *
   * @param cert leaf certificate from ownership voucher
   */
  private void verifyLeafCertPrivileges(X509Certificate cert)
      throws InvalidOwnershipVoucherException {
    if (cert.getKeyUsage() != null) {
      if (!(cert.getKeyUsage()[0])) {
        throw new InvalidOwnershipVoucherException(
            "Digital signature is not allowed for the device certificate");
      }
    }
  }

  /**
   * Verifies certificate chain.
   *
   * @param certChain ownership voucher device certificate chain
   */
  public void verifyCertChain(Composite certChain) {
    X509Certificate leafCertificate = null;
    try {
      final CertPath cp = getCertPath(certChain);
      leafCertificate = (X509Certificate) cp.getCertificates().get(0);
    } catch (CertificateException e) {
      throw new CryptoServiceException(e);
    }

    verifyLeafPubKeyData(leafCertificate);
    verifyLeafCertPrivileges(leafCertificate);
  }

  /**
   * Verifies ownership voucher.
   *
   * @param voucher ownership voucher
   */
  public void verifyVoucher(Composite voucher) {

    verifyHash(
            voucher.getAsComposite(Const.OV_HEADER).getAsComposite(Const.OVH_CERT_CHAIN_HASH),
            voucher.getAsComposite(Const.OV_DEV_CERT_CHAIN).toBytes());
    verifyCertChain(voucher.getAsComposite(Const.OV_DEV_CERT_CHAIN));
    verify(voucher.getAsComposite(Const.OV_DEV_CERT_CHAIN));
  }

  /**
   * Produces a COSE Signature.
   *
   * @param signingKey The signing key.
   * @param payload    The payload to sign.
   * @param coseSignatureAlg The COSE algorithm that determines the signature algorithm.
   * @return The resulting COSE Signature.
   */
  public Composite sign(PrivateKey signingKey, byte[] payload, int coseSignatureAlg) {

    final byte[] protectedHeader = Composite.newMap()
        .set(Const.COSE_ALG, coseSignatureAlg)
        .toBytes();

    final Composite cos = Composite.newArray()
        .set(Const.COSE_SIGN1_PROTECTED, protectedHeader)
        .set(Const.COSE_SIGN1_UNPROTECTED, Composite.newMap())
        .set(Const.COSE_SIGN1_PAYLOAD, payload);

    try {
      final String algName = getSignatureAlgorithm(coseSignatureAlg);

      final Signature signer = getSignatureInstance(algName);
      signer.initSign(signingKey);

      // Signature must be computed over a sig_structure:
      // Sig_structure = [
      //   context : "Signature" / "Signature1" / "CounterSignature",
      //   body_protected : empty_or_serialized_map,
      //   external_aad : bstr,
      //   payload : bstr
      // ]
      //
      // See the COSE RFC 8152 for details on this.

      Composite sigStruct = Composite.newArray()
          .set(Const.FIRST_KEY, "Signature1")
          .set(Const.SECOND_KEY, protectedHeader)
          .set(Const.THIRD_KEY, new byte[0])
          .set(Const.FOURTH_KEY, payload);

      signer.update(sigStruct.toBytes());
      final byte[] sig = signer.sign();

      byte[] formattedSig = sig;
      if (algName.endsWith("withECDSA")) {

        // COSE ECDSA signatures are not DER, but are instead R|S, with R and S padded to
        // key length and concatenated.  We must convert.
        BigInteger r;
        BigInteger s;
        try (ByteArrayInputStream bin = new ByteArrayInputStream(sig);
            ASN1InputStream in = new ASN1InputStream(bin)) {

          DLSequence sequence = (DLSequence) in.readObject();
          r = ((ASN1Integer) sequence.getObjectAt(0)).getPositiveValue();
          s = ((ASN1Integer) sequence.getObjectAt(1)).getPositiveValue();
        }

        // PKCS11 keys cannot be directly interrogated, guess key size from associated algorithm IDs
        final int size;
        switch (coseSignatureAlg) {
          case Const.COSE_ES256:
            size = 32;
            break;
          case Const.COSE_ES384:
            size = 48;
            break;
          default:
            throw new InvalidParameterException("coseSignatureAlg " + coseSignatureAlg);
        }
        formattedSig = new byte[2 * size];
        writeBigInteger(r, formattedSig, 0, size);
        writeBigInteger(s, formattedSig, size, size);
      }

      cos.set(Const.COSE_SIGN1_SIGNATURE, formattedSig);
      return cos;

    } catch (Exception e) {
      throw new CryptoServiceException(e);
    }
  }

  /**
   * Write a BigInteger into a fixed-length buffer.
   */
  static void writeBigInteger(BigInteger src, byte[] dest, int destPos, int length) {
    byte[] intbuf = src.toByteArray(); // min #bits, with one sign bit guaranteed!
    int byteLen = src.bitLength() / Byte.SIZE + 1;

    if (byteLen >= length) { // the bigint fits exactly, or must be truncated.
      System.arraycopy(intbuf, byteLen - length, dest, destPos, length);
    } else { // the bigint must be padded to fill the field
      int pad = length - byteLen;
      Arrays.fill(dest, destPos,  pad + destPos, (byte)0);
      System.arraycopy(intbuf, byteLen, dest, pad + destPos, byteLen);
    }
  }

  /**
   * Computes hash of data using HMAC.
   *
   * <p>The Hash type must be one of the following.
   * <p>HMAC_SHA_256</p>
   * <p>HMAC_SHA_384</p>
   * <p>HMAC_SHA_256_KX</p>
   * <p>HMAC_SHA_512_KX</p>
   * <p>HMAC_SHA_384_KX</p>
   *
   * @param hashType The hash algorithm id to use
   * @param secret   Secret key.
   * @param data     The data to sign.
   * @return Hash composite with HASH_TYPE and HASH keys.
   */
  public Composite hash(int hashType, byte[] secret, byte[] data) {

    try {
      final String algName = getHashAlgorithm(hashType);
      final Mac mac = getMacInstance(algName);

      final byte[] macData;
      final SecretKey secretKey = getHmacKey(secret, algName);
      try {
        mac.init(secretKey);
        macData = mac.doFinal(data);
      } finally {
        try {
          secretKey.destroy();
        } catch (DestroyFailedException e) {
          // many key implementations don't support destruction correctly - this exception
          // is expected and can be ignored.
        }
      }

      return Composite.newArray()
          .set(Const.HASH_TYPE, hashType)
          .set(Const.HASH, macData);

    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new CryptoServiceException(e);
    }
  }

  /**
   * Computes hash of data using SHA.
   * <p>The Composite must contain a HAST_TYPE key set to one of the following:</p>
   * <p>SHA_256</p>
   * <p>SHA_384</p>
   * <p>SHA_512</p>
   *
   * @param hashType The hash algorithm to use.
   * @param data     The data to sign.
   * @return Hash composite with HASH_TYPE and HASH keys.
   */
  public Composite hash(int hashType, byte[] data) {
    try {
      final String algName = getHashAlgorithm(hashType);
      final MessageDigest digest = getDigestInstance(algName);

      final byte[] result = digest.digest(data);

      return Composite.newArray()
          .set(Const.HASH_TYPE, hashType)
          .set(Const.HASH, result);

    } catch (NoSuchAlgorithmException e) {
      throw new CryptoServiceException(e);
    }
  }

  protected String getValidatorAlgorithm() {
    return Const.VALIDATOR_ALG_NAME;
  }

  protected String getCertPathAlgorithm() {
    return Const.X509_ALG_NAME;
  }

  /**
   * Gets a Certificate from encoded DER bytes.
   *
   * @param cf  A certificate factory.
   * @param der A der encoded certificate
   * @return The Certificate.
   * @throws CertificateException If the DER value is not a valid certificate.
   */
  public Certificate getCertificate(CertificateFactory cf, byte[] der)
      throws CertificateException {
    final ByteArrayInputStream in = new ByteArrayInputStream(der);
    return cf.generateCertificate(in);
  }

  /**
   * Gets certificate path from the COSE chain.
   *
   * @param chain A COSE chain.
   * @return The Certificate path.
   * @throws CertificateException If the chain is not a valid set of certificates.
   */
  public CertPath getCertPath(Composite chain) throws CertificateException {

    final CertificateFactory cf = CertificateFactory
        .getInstance(getCertPathAlgorithm());

    final List<Certificate> list = new ArrayList<>();
    for (int i = 0; i < chain.size(); i++) {
      list.add(getCertificate(cf, chain.getAsBytes(i)));
    }

    return cf.generateCertPath(list);

  }

  /**
   * Gets the certificate path parameters use for verification.
   *
   * @param anchors The trusted anchors used to verify the path.
   * @return The certificate path parameters.
   * @throws InvalidAlgorithmParameterException If the parameters are not valid.
   */
  protected CertPathParameters getCertPathParameters(Set<TrustAnchor> anchors)
      throws InvalidAlgorithmParameterException {
    final PKIXParameters params = new PKIXParameters(anchors);
    params.setRevocationEnabled(false);
    return params;
  }

  /**
   * Creates a key pair.
   *
   * @param algName The Keypair algorithm.
   * @return the public/private key pair.
   */
  public KeyPair createKeyPair(String algName) {

    if (algName.equals(Const.SECP256R1_CURVE_NAME)
        || algName.equals(Const.SECP384R1_CURVE_NAME)) {

      try {
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(algName);
        KeyPairGenerator kg = KeyPairGenerator.getInstance(Const.EC_ALG_NAME);
        kg.initialize(ecSpec, getSecureRandom());
        return kg.generateKeyPair();
      } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
        throw new CryptoServiceException(e);
      }
      //} else if (algName.equals("")) {
      //
    }
    throw new CryptoServiceException(new NoSuchAlgorithmException(algName));
  }

  /**
   * Writes the length value to the output stream.
   *
   * @param out The Output stream to write to.
   * @param len The length to write.
   * @throws IOException If an exception occurs while writing the length.
   */
  protected void writeLen(OutputStream out, int len) throws IOException {
    out.write((byte) (len >> 8));
    out.write((byte) len);
  }

  /**
   * Decode a ECDH Message.
   *
   * <p>This is a 3 part encoded message with each part length prefixed.</p>
   * <p>bstr[blen(Ax), Ax, blen(Ay), Ay, blen(OwnerRandom), OwnerRandom]</p>
   * <p>bstr[blen(Bx), Bx, blen(By), By, blen(DeviceRandom), DeviceRandom]</p>
   *
   * @param message The 3 Part message.
   * @return A Composite with all 3 parts decoded.
   */
  protected Composite decodeEcdhMessage(byte[] message) {
    try (ByteArrayInputStream bis = new ByteArrayInputStream(message)) {
      Composite result = Composite.newArray();

      for (int i = 0; i < Const.FOURTH_KEY; i++) {

        //get the size of the three part message
        int len = (short) (((bis.read() & 0xFF) << 8) | (bis.read() & 0xFF));
        if (len < 0 || len >= message.length) {
          throw new IllegalArgumentException();
        }
        byte[] value = new byte[len];
        bis.read(value);
        result.set(result.size(), value);
      }
      return result;
    } catch (IOException e) {
      throw new CryptoServiceException(e);
    }
  }

  /**
   * Gets the ECDH Key Exchange message.
   *
   * @param curveName  The EC Curve to use.
   * @param randomSize The size of the random data.
   * @param party      The party to the exchange ("A" or "B").
   * @return A composite with state information.
   */
  protected Composite getEcdhMessage(String curveName, int randomSize, String party) {

    final KeyPair kp = createKeyPair(curveName);
    final ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
    final int bitLength = publicKey.getParams().getCurve().getField().getFieldSize();
    final int byteLength = bitLength / Byte.SIZE;
    final byte[] randomBytes = getRandomBytes(randomSize);

    //bstr[blen(x), x, blen(y), y, blen(Random), Random]
    final byte[] x = adjustBigBuffer(publicKey.getW().getAffineX().toByteArray(), byteLength);
    final byte[] y = adjustBigBuffer(publicKey.getW().getAffineY().toByteArray(), byteLength);

    try (ByteArrayOutputStream bao = new ByteArrayOutputStream()) {
      writeLen(bao, x.length);
      bao.writeBytes(x);
      writeLen(bao, y.length);
      bao.writeBytes(y);
      writeLen(bao, randomBytes.length);
      bao.writeBytes(randomBytes);
      return Composite.newArray()
          .set(Const.FIRST_KEY, bao.toByteArray())
          .set(Const.SECOND_KEY, Const.ECDH_ALG_NAME)
          .set(Const.THIRD_KEY, kp.getPrivate().getFormat())
          .set(Const.FOURTH_KEY, kp.getPrivate().getEncoded())
          .set(Const.FIFTH_KEY, party);
    } catch (IOException ioException) {
      throw new CryptoServiceException(ioException);
    }
  }

  protected KeyExchangeResult getEcdhSharedSecret(byte[] message, Composite ownState) {
    try {
      final Composite theirState = decodeEcdhMessage(message);
      final byte[] theirX = theirState.getAsBytes(Const.FIRST_KEY);
      final byte[] theirY = theirState.getAsBytes(Const.SECOND_KEY);
      final byte[] theirRandom = theirState.getAsBytes(Const.THIRD_KEY);

      final byte[] encoded = ownState.getAsBytes(Const.FOURTH_KEY);
      final PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(encoded);
      final KeyFactory factory = getKeyFactoryInstance(Const.EC_ALG_NAME);
      final KeyAgreement keyAgreement = getKeyAgreementInstance(Const.ECDH_ALG_NAME);
      final ECPrivateKey ownKey = (ECPrivateKey) factory.generatePrivate(privateSpec);
      final byte[] sharedSecret;
      try {

        final ECPoint w = new ECPoint(new BigInteger(1, theirX), new BigInteger(1, theirY));
        final ECPublicKeySpec publicSpec = new ECPublicKeySpec(w, ownKey.getParams());

        final PublicKey theirKey = factory.generatePublic(publicSpec);

        keyAgreement.init(ownKey);
        keyAgreement.doPhase(theirKey, true);
        sharedSecret = keyAgreement.generateSecret();

      } finally {
        try {
          ownKey.destroy();
        } catch (DestroyFailedException e) {
          // many key implementations don't support destruction correctly - this exception
          // is expected and can be ignored.
        }
      }

      try {

        final Composite ownMessage = decodeEcdhMessage(ownState.getAsBytes(Const.FIRST_KEY));
        final byte[] ownRandom = ownMessage.getAsBytes(Const.THIRD_KEY);
        final ByteBuffer buffer = ByteBuffer
            .allocate(sharedSecret.length + ownRandom.length + theirRandom.length);
        buffer.put(sharedSecret);

        final String party = ownState.getAsString(Const.FIFTH_KEY);
        if (party.equals(Const.KEY_EXCHANGE_A)) {
          //A is owner
          buffer.put(theirRandom);
          buffer.put(ownRandom);
        } else if (party.equals(Const.KEY_EXCHANGE_B)) {
          //B is device
          buffer.put(ownRandom);
          buffer.put(theirRandom);
        } else {
          throw new IllegalArgumentException();
        }

        buffer.flip();
        return new KeyExchangeResult(Composite.unwrap(buffer), new byte[0]);

      } finally {
        Arrays.fill(sharedSecret, (byte)0);
      }
    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
      throw new CryptoServiceException(e);
    }
  }

  /**
   * Gets the key exchange shared secrete.
   *
   * @param message  The key exchange message.
   * @param ownState The state of the key exchange.
   * @param decryptionKey The decryption key for use in asymmetric exchanges
   * @return The shared secrete based on the state and message.
   */
  public KeyExchangeResult getSharedSecret(byte[] message, Composite ownState, Key decryptionKey) {

    final String alg = ownState.getAsString(Const.SECOND_KEY);
    switch (alg) {
      case Const.ECDH_ALG_NAME:
        return getEcdhSharedSecret(message, ownState);
      case Const.ASYMKEX2048_ALG_NAME:
      case Const.ASYMKEX3072_ALG_NAME:
        return getAsymkexSharedSecret(message, ownState, decryptionKey);
      case DiffieHellman.DH14_ALG_NAME:
      case DiffieHellman.DH15_ALG_NAME:
        // All owner states have our message as element 0 (FIRST_KEY) and the algorithm name
        // in element 1 (SECOND_KEY).
        //
        // Restore our keyExchange from the KE state,
        // which is element 2 (THIRD_KEY) in the owner state.
        DiffieHellman.KeyExchange ke = new KeyExchange(ownState.getAsComposite(Const.THIRD_KEY));
        try {
          return new KeyExchangeResult(
              ke.computeSharedSecret(new BigInteger(1, message)).toByteArray(), new byte[0]);
        } finally {
          try {
            ke.destroy();
          } catch (DestroyFailedException e) {
            // this should never happen
            assert false;
            throw new RuntimeException(e);
          }
        }
      default:
        throw new CryptoServiceException(new NoSuchAlgorithmException(alg));
    }
  }

  /**
   * Gets the Key Exchange message.
   * <p>Creates ExchangeA if called on the server</p>
   * <p>Creates ExchangeB if called on the device</p>
   *
   * @param kexSuiteName The name of the Key Exchange Suite.
   * @param party        The party to the Key Ecxhange (A or B)
   * @param ownerKey     The owner key, required for some asymmetric exchanges
   * @return A composite state value with the fist key set to the message.
   */
  public Composite getKeyExchangeMessage(String kexSuiteName, String party, Key ownerKey) {

    switch (kexSuiteName) {
      case Const.ECDH_ALG_NAME:
        return getEcdhMessage(Const.SECP256R1_CURVE_NAME, Const.ECDH_256_RANDOM_SIZE, party);
      case Const.ECDH384_ALG_NAME:
        return getEcdhMessage(Const.SECP384R1_CURVE_NAME, Const.ECDH_384_RANDOM_SIZE, party);
      case Const.ASYMKEX2048_ALG_NAME:
        return getAsymkexMessage(
            Const.ASYMKEX2048_ALG_NAME, Const.ASYMKEX2048_RANDOM_SIZE, party, ownerKey);
      case Const.ASYMKEX3072_ALG_NAME:
        return getAsymkexMessage(
            Const.ASYMKEX3072_ALG_NAME, Const.ASYMKEX3072_RANDOM_SIZE, party, ownerKey);
      case DiffieHellman.DH14_ALG_NAME:
      case DiffieHellman.DH15_ALG_NAME:
        DiffieHellman.KeyExchange ke = DiffieHellman.buildKeyExchange(kexSuiteName);
        try {
          return Composite.newArray()
              .set(Const.FIRST_KEY, ke.getMessage().toByteArray())
              .set(Const.SECOND_KEY, kexSuiteName)
              .set(Const.THIRD_KEY, ke.getState());
        } finally {
          try {
            ke.destroy();
          } catch (DestroyFailedException e) {
            // this should never happen
            assert false;
            throw new RuntimeException(e);
          }
        }
      default:
        throw new CryptoServiceException(new NoSuchAlgorithmException(kexSuiteName));
    }
  }

  protected Composite getAsymkexMessage(
      String algName, int randomSize, String party, Key encryptionKey) {

    switch (party) {

      case Const.KEY_EXCHANGE_A:

        byte[] a = new byte[randomSize];
        getSecureRandom().nextBytes(a);

        return Composite.newArray()
            .set(Const.FIRST_KEY, a)
            .set(Const.SECOND_KEY, algName)
            .set(Const.THIRD_KEY, Const.KEY_EXCHANGE_A)
            .set(Const.FOURTH_KEY, randomSize);

      case Const.KEY_EXCHANGE_B:

        byte[] b = new byte[randomSize];
        getSecureRandom().nextBytes(b);

        byte[] xb;
        try {
          Cipher cipher = Cipher.getInstance(Const.ASYMKEX_CIPHER_NAME, BCPROV);
          cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, getSecureRandom());
          xb = cipher.doFinal(b);
        } catch (GeneralSecurityException e) {
          throw new RuntimeException(e);
        }

        return Composite.newArray()
            .set(Const.FIRST_KEY, xb)
            .set(Const.SECOND_KEY, algName)
            .set(Const.THIRD_KEY, Const.KEY_EXCHANGE_B)
            .set(Const.FOURTH_KEY, randomSize)
            .set(Const.FIFTH_KEY, b);

      default:
        throw new IllegalArgumentException(party);
    }
  }

  protected KeyExchangeResult getAsymkexSharedSecret(
      byte[] message, Composite ownState, Key decryptionKey) {

    String party = ownState.getAsString(Const.THIRD_KEY);

    switch (party) {
      case Const.KEY_EXCHANGE_A:

        byte[] b;
        try {
          Cipher cipher = Cipher.getInstance(Const.ASYMKEX_CIPHER_NAME, BCPROV);
          cipher.init(Cipher.DECRYPT_MODE, decryptionKey, getSecureRandom());
          b = cipher.doFinal(message);
        } catch (GeneralSecurityException e) {
          throw new RuntimeException(e);
        }
        return new KeyExchangeResult(b, ownState.getAsBytes(Const.FIRST_KEY));

      case Const.KEY_EXCHANGE_B:
        return new KeyExchangeResult(ownState.getAsBytes(Const.FIFTH_KEY), message);

      default:
        throw new IllegalArgumentException(party);
    }

  }

  private boolean isSimpleEncryptedMessage(int aesType) {
    return Const.COSEAES128GCM == aesType
        || Const.COSEAES256GCM == aesType
        || Const.COSEAESCCM_64_128_128 == aesType
        || Const.COSEAESCCM_64_128_256 == aesType;
  }

  private int cipherNameToAesType(String cipherName) {
    int aesType;
    if (cipherName.equals(Const.AES128_CTR_HMAC256_ALG_NAME)) {
      aesType = Const.COSEAES128CTR;
    } else if (cipherName.equals(Const.AES128_CBC_HMAC256_ALG_NAME)) {
      aesType = Const.COSEAES128CBC;
    } else if (cipherName.equals(Const.AES256_CBC_HMAC384_ALG_NAME)) {
      aesType = Const.COSEAES256CBC;
    } else if (cipherName.equals(Const.AES256_CTR_HMAC384_ALG_NAME)) {
      aesType = Const.COSEAES256CTR;
    } else if (cipherName.equals(Const.AES128_GCM_ALG_NAME)) {
      aesType = Const.COSEAES128GCM;
    } else if (cipherName.equals(Const.AES256_GCM_ALG_NAME)) {
      aesType = Const.COSEAES256GCM;
    } else if (cipherName.equals(Const.AES_CCM_64_128_128_ALG_NAME)) {
      aesType = Const.COSEAESCCM_64_128_128;
    } else if (cipherName.equals(Const.AES_CCM_64_128_256_ALG_NAME)) {
      aesType = Const.COSEAESCCM_64_128_256;
    } else {
      throw new CryptoServiceException(new NoSuchAlgorithmException());
    }

    return aesType;
  }

  private byte[] buildEncrypt0ProtectedHeader(int aesType) {

    byte[] protectedHeader = Composite.newMap()
        .set(Const.ETM_AES_PLAIN_TYPE, aesType)
        .toBytes();
    return protectedHeader;
  }

  protected Composite encryptThenMac(byte[] secret, byte[] ciphered, byte[] iv, String cipherName) {

    int aesType = cipherNameToAesType(cipherName);
    byte[] protectedHeader = buildEncrypt0ProtectedHeader(aesType);

    Composite cose0 = Composite.newArray()
        .set(Const.COSE_SIGN1_PROTECTED, protectedHeader)
        .set(Const.COSE_SIGN1_UNPROTECTED,
            Composite.newMap()
                .set(Const.ETM_AES_IV, iv))
        .set(Const.COSE_SIGN1_PAYLOAD, ciphered);

    if (isSimpleEncryptedMessage(aesType)) { // not all encrypted messages use the 'composed' type
      return cose0;
    }

    int hmacType;
    if (cipherName.equals(Const.AES128_CTR_HMAC256_ALG_NAME)
        || cipherName.equals(Const.AES128_CBC_HMAC256_ALG_NAME)) {
      hmacType = Const.HMAC_SHA_256;
    } else if (cipherName.equals(Const.AES256_CBC_HMAC384_ALG_NAME)
        || cipherName.equals(Const.AES256_CTR_HMAC384_ALG_NAME)) {
      hmacType = Const.HMAC_SHA_384;
    } else {
      throw new CryptoServiceException(new NoSuchAlgorithmException());
    }
    byte[] payload = cose0.toBytes();
    Composite mac = hash(hmacType, secret, payload);

    protectedHeader = Composite.newMap()
        .set(Const.ETM_MAC_TYPE, hmacType)
        .toBytes();
    Composite mac0 = Composite.newArray()
        .set(Const.COSE_SIGN1_PROTECTED, protectedHeader)
        .set(Const.COSE_SIGN1_UNPROTECTED, Composite.newMap())
        .set(Const.COSE_SIGN1_PAYLOAD, payload)
        .set(Const.COSE_SIGN1_SIGNATURE, mac.getAsBytes(Const.HASH));

    return mac0;
  }

  // Key Derivation Function (KDF).
  //
  // See NIST SP 800-108, FDO spec section 3.6.4
  // Where possible, variable names are chosen to match those documents.
  protected byte[] kdf(
      int size,      // the number of bits to derive (L)
      String prfId,  // the JCE ID of the PRF to use
      KeyExchangeResult kxResult) // the sharedSecret and contextRandom
      throws
      InvalidKeyException,
      IOException,
      NoSuchAlgorithmException {

    Mac prf = Mac.getInstance(prfId);
    prf.init(new SecretKeySpec(kxResult.shSe, prfId));

    final int h = prf.getMacLength() * Byte.SIZE; // (h) the length (in bits) of the PRF output
    final int l = size;  // (L) the length (in bits) of the derived keying material
    // (n) the number of iterations of the PRF needed to generate L bits of
    // keying material.
    final int n = Double.valueOf(Math.ceil((double)l / (double)h)).intValue();

    ByteArrayOutputStream result = new ByteArrayOutputStream();

    for (int i = 1; n >= i; i++) { // NIST SP 800-108 loops from 1 to n, not 0 to n - 1!

      prf.reset();

      // write K(i) to the prf...
      prf.update((byte)i); // [i]2
      prf.update("FIDO-KDF".getBytes(StandardCharsets.UTF_8)); // Label
      prf.update((byte)0); // 0x00, separator
      prf.update("AutomaticOnboardTunnel".getBytes(StandardCharsets.UTF_8)); // Context (part 1)
      prf.update(kxResult.contextRand);                                      // Context (part 2)
      prf.update((byte)((l >> 8) & 0xff)); // [L]2, upper byte
      prf.update((byte)(l & 0xff));        // [L]2, lower byte
      result.write(prf.doFinal());  // append K(i) to the cumulative result
    }

    return result.toByteArray();
  }

  protected byte[] getCtrIv() {
    ByteBuffer buffer = ByteBuffer.allocate(Const.IV_SIZE);
    byte[] seed = getRandomBytes(Const.IV_SEED_SIZE);
    buffer.put(seed);
    buffer.put(new byte[]{0, 0, 0, 0});
    buffer.flip();
    return Composite.unwrap(buffer);
  }

  protected void updateIv(int cipheredLen, Composite state) {
    final String cipherName = state.getAsString(Const.FIRST_KEY);
    final ByteBuffer iv = state.getAsByteBuffer(Const.THIRD_KEY);
    long counter = state.getAsNumber(Const.FOURTH_KEY).longValue();
    if (cipherName.indexOf("/CTR/") > 0) {
      //the last 4 bytes of the iv will be the counter
      byte[] seed = new byte[Const.IV_SEED_SIZE];
      iv.get(seed);

      int blockCount = 1 + (cipheredLen - 1) / Const.IV_SIZE;
      counter += blockCount;

      ByteBuffer buffer = ByteBuffer.allocate(Const.IV_SIZE);
      buffer.put(seed);

      buffer.putInt((int) counter);
      buffer.flip();

      state.set(Const.THIRD_KEY, Composite.unwrap(buffer));
      state.set(Const.FOURTH_KEY, counter);
    } else if (cipherName.indexOf("/CBC/") > 0) {
      byte[] seed = new byte[Const.IV_SEED_SIZE];
      iv.get(seed);

      byte[] rnd = getRandomBytes(4);

      ByteBuffer buffer = ByteBuffer.allocate(Const.IV_SIZE);
      buffer.put(seed);
      buffer.put(rnd);
      buffer.flip();
      state.set(Const.THIRD_KEY, Composite.unwrap(buffer));
    } else {
      throw new CryptoServiceException(new NoSuchAlgorithmException());
    }
  }

  private int coseEncrypt0ToAesType(Composite encrypt0) {
    // aesType is encoded in the protected header, and lets us decide if this is a simple
    // or composed message.
    final byte[] protectedHeader = encrypt0.getAsBytes(Const.COSE_SIGN1_PROTECTED);
    final Composite prh = Composite.fromObject(protectedHeader);
    final int aesType = prh.getAsNumber(Const.ETM_AES_PLAIN_TYPE).intValue();

    return aesType;
  }

  private Cipher aesTypeToCipher(int aesType)
      throws NoSuchPaddingException, NoSuchAlgorithmException {

    switch (aesType) {
      case Const.COSEAES128CTR:
      case Const.COSEAES256CTR:
        return Cipher.getInstance("AES/CTR/NoPadding");

      case Const.COSEAES128CBC:
      case Const.COSEAES256CBC:
        return Cipher.getInstance("AES/CBC/PKCS7Padding", BCPROV);

      case Const.COSEAES128GCM:
      case Const.COSEAES256GCM:
        return Cipher.getInstance("AES/GCM/NoPadding");

      default:
        throw new UnsupportedOperationException("AESType: " + aesType);
    }
  }

  /**
   * Decrypts a message.
   *
   * @param message The ciphered message.
   * @param state   The crypto state.
   * @return The decrypted message.
   */
  public byte[] decrypt(Composite message, Composite state) {
    try {
      final Composite keys = state.getAsComposite(Const.SECOND_KEY);
      final byte[] sek = keys.getAsBytes(Const.FIRST_KEY);
      final byte[] svk = keys.getAsBytes(Const.SECOND_KEY);
      final Key keySpec = new SecretKeySpec(sek, Const.AES);

      final Composite cose0;
      int aesType = coseEncrypt0ToAesType(message);
      final byte[] aad;

      if (isSimpleEncryptedMessage(aesType)) {

        cose0 = message;
        aad = Composite.newArray()
            .set(0, Const.COSE_CONTEXT_ENCRYPT0)
            .set(1, cose0.getAsBytes(Const.COSE_SIGN1_PROTECTED))
            .set(2, new byte[0])
            .toBytes();

      } else { // legacy (composed) message

        cose0 = Composite.fromObject(message.getAsBytes(Const.COSE_SIGN1_PAYLOAD));
        aad = new byte[0];
        int macType = aesType; // what we thought was AES type is really MAC type, and...
        aesType = coseEncrypt0ToAesType(cose0); // the REAL AES type is wrapped
        final byte[] mac1 = message.getAsBytes(Const.COSE_SIGN1_SIGNATURE);

        Composite mac2 = hash(macType, svk, cose0.toBytes());
        this.verifyBytes(mac1, mac2.getAsBytes(Const.HASH));

      }

      final Composite uph = cose0.getAsComposite(Const.COSE_SIGN1_UNPROTECTED);
      final byte[] iv = uph.getAsBytes(Const.ETM_AES_IV);



      if (isCcmCipher(aesType)) {

        final byte[] ciphered = cose0.getAsBytes(Const.COSE_SIGN1_PAYLOAD);
        return ccmEncrypt(false, ciphered, sek, iv, aad);

      } else {

        AlgorithmParameterSpec cipherParams;
        if (isGcmCipher(aesType)) { // GCM ciphers use GCMParameterSpec
          cipherParams = new GCMParameterSpec(Const.GCM_TAG_LENGTH, iv);
        } else {
          cipherParams = new IvParameterSpec(iv);
        }

        final Cipher cipher = aesTypeToCipher(aesType);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, cipherParams);
        cipher.updateAAD(aad, 0, aad.length);

        final byte[] ciphered = cose0.getAsBytes(Const.COSE_SIGN1_PAYLOAD);
        return cipher.doFinal(ciphered);

      }
    } catch (NoSuchPaddingException | NoSuchAlgorithmException
        | InvalidAlgorithmParameterException | InvalidKeyException
        | BadPaddingException | IllegalBlockSizeException e) {
      throw new CryptoServiceException(e);
    }
  }

  private boolean isCtrCipher(String name) {
    return Const.AES128_CTR_HMAC256_ALG_NAME.equals(name)
        || Const.AES256_CTR_HMAC384_ALG_NAME.equals(name);
  }

  private boolean isGcmCipher(String name) {
    return Const.AES128_GCM_ALG_NAME.equals(name)
        || Const.AES256_GCM_ALG_NAME.equals(name);
  }

  private boolean isGcmCipher(int type) {
    return Const.COSEAES128GCM == type || Const.COSEAES256GCM == type;
  }

  private boolean isCcmCipher(String name) {
    return Const.AES_CCM_64_128_128_ALG_NAME.equals(name)
        || Const.AES_CCM_64_128_256_ALG_NAME.equals(name);
  }

  private boolean isCcmCipher(int type) {
    return Const.COSEAESCCM_64_128_128 == type || Const.COSEAESCCM_64_128_256 == type;
  }

  private byte[] ccmEncrypt(
      boolean forEncryption, byte[] plainText, byte[] sek, byte[] iv, byte[] aad) {

    final int macSize = 128; // All CCM cipher modes use this size

    BlockCipher engine = new AESEngine();
    AEADParameters params = new AEADParameters(new KeyParameter(sek), macSize, iv, aad);
    CCMBlockCipher cipher = new CCMBlockCipher(engine);
    cipher.init(forEncryption, params);
    byte[] outputText = new byte[cipher.getOutputSize(plainText.length)];
    int outputLen = cipher.processBytes(plainText, 0, plainText.length, outputText, 0);
    try {
      cipher.doFinal(outputText, outputLen);
    } catch (InvalidCipherTextException e) {
      throw new RuntimeException(e);
    }

    return outputText;
  }

  /**
   * Encrypts a message.
   *
   * @param payload The payload to encrypt.
   * @param state   The saved crypto state.
   * @return The encrypted message and state.
   */
  public Composite encrypt(byte[] payload, Composite state) {
    try {
      final String cipherName = state.getAsString(Const.FIRST_KEY);
      final Composite keys = state.getAsComposite(Const.SECOND_KEY);
      final byte[] sek = keys.getAsBytes(Const.FIRST_KEY);
      final byte[] sev = keys.getAsBytes(Const.SECOND_KEY);
      final Key keySpec = new SecretKeySpec(sek, Const.AES);

      final byte[] iv;
      if (isCtrCipher(cipherName)) {
        iv = state.getAsBytes(Const.THIRD_KEY);
      } else if (isGcmCipher(cipherName)) { // GCM uses a 12-byte IV
        iv = getRandomBytes(12);
      } else if (isCcmCipher(cipherName)) { // CCM modes use a 7-byte nonce
        iv = getRandomBytes(7);
      } else { // all other ciphers use a random IV, AES only uses 16 bytes despite key length
        iv = getRandomBytes(Const.IV_SIZE);
      }

      int aesType = cipherNameToAesType(cipherName);
      byte[] protectedHeader = buildEncrypt0ProtectedHeader(aesType);

      byte[] aad;
      if (isCcmCipher(cipherName) || isGcmCipher(cipherName)) {
        // Simple encrypt0 types use AAD as described in the COSE spec
        aad = Composite.newArray()
            .set(0, Const.COSE_CONTEXT_ENCRYPT0)
            .set(1, protectedHeader)
            .set(2, new byte[0])
            .toBytes();
      } else {
        aad = new byte[0];
      }

      final byte[] ciphered;
      if (isCcmCipher(cipherName)) {

        ciphered = ccmEncrypt(true, payload, sek, iv, aad);

      } else {

        AlgorithmParameterSpec cipherParams;
        if (isGcmCipher(cipherName)) { // GCM ciphers use GCMParameterSpec

          // According to NIST SP800.38D section 5.2.1.2, the tag length can
          // only be 96, 104, 112, 120, or 128 bits.
          if (!Arrays.asList(96, 104, 112, 120, 128).contains(Const.GCM_TAG_LENGTH)) {
            throw new IllegalArgumentException("illegal GCM tag length");
          }
          cipherParams = new GCMParameterSpec(Const.GCM_TAG_LENGTH, iv);

        } else {
          cipherParams = new IvParameterSpec(iv);
        }

        final Cipher cipher = getCipherInstance(cipherName);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, cipherParams);

        // Since AAD can be no more than 2^64 - 1 bits and a Java array can be
        // no longer than 2^31 - 1 elements, there's no need to length check
        // the AAD.
        cipher.updateAAD(aad, 0, aad.length);

        // Since GCM plaintext can be no more than 2^39 - 256 bits and a Java
        // array can be no longer than 2^31 - 1 elements, there's no need
        // to length check the payload.
        ciphered = cipher.doFinal(payload);

      }

      Composite message = encryptThenMac(sev, ciphered, iv, cipherName);

      if (isCtrCipher(cipherName)) {
        updateIv(ciphered.length, state);
      }

      return message;

    } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException
        | InvalidAlgorithmParameterException | InvalidKeyException
        | BadPaddingException | IllegalBlockSizeException e) {
      throw new CryptoServiceException(e);
    }
  }

  /**
   * gets the the encryption state.
   *
   * @param kxResult    Shared secret and contextRandom.
   * @param cipherSuite The cipher suite to use.
   * @return A Composite encryption state.
   */
  public Composite getEncryptionState(KeyExchangeResult kxResult, String cipherSuite) {

    final Composite state = Composite.newArray();

    state.set(Const.FIRST_KEY, cipherSuite);

    // The second key in the state object must be a Composite of at most two values:
    // the SEK and the SVK, or
    // the SEVK, which is how we'll treat a single (SEK) key.
    final int sekSize;
    final int svkSize;
    final String prfId;

    if (cipherSuite.equals(Const.AES128_CTR_HMAC256_ALG_NAME)
          || cipherSuite.equals(Const.AES128_CBC_HMAC256_ALG_NAME)) {

      // 128-bit AES (SEK), 256-bit HMAC (SVK)
      sekSize = 16;
      svkSize = 32;
      prfId   = Const.HMAC_256_ALG_NAME; // see table in FDO spec 4.4

    } else if (cipherSuite.equals(Const.AES256_CTR_HMAC384_ALG_NAME)
          || cipherSuite.equals(Const.AES256_CBC_HMAC384_ALG_NAME)) {

      // 256-bit AES (SEK), 512-bit HMAC (SVK) (HMAC-384 needs a 512-bit key)
      sekSize = 32;
      svkSize = 64;
      prfId   = Const.HMAC_384_ALG_NAME; // see table in FDO spec 4.4

    } else if (cipherSuite.equals(Const.AES128_GCM_ALG_NAME)
          || cipherSuite.equals(Const.AES_CCM_64_128_128_ALG_NAME)) {

      // 128-bit AES (SEVK)
      sekSize = 16;
      svkSize = 0;
      prfId   = Const.HMAC_256_ALG_NAME; // see table in FDO spec 4.4

    } else if (cipherSuite.equals(Const.AES256_GCM_ALG_NAME)
          || cipherSuite.equals(Const.AES_CCM_64_128_256_ALG_NAME)) {

      // 256-bit AES (SEVK)
      sekSize = 32;
      svkSize = 0;
      prfId   = Const.HMAC_256_ALG_NAME; // see table in FDO spec 4.4

    } else {
      throw new IllegalArgumentException("unrecognized cipher suite: " + cipherSuite);
    }

    final byte[] keyMaterial;
    try {
      keyMaterial = kdf((sekSize + svkSize) * Byte.SIZE, prfId, kxResult);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    // Build the composite containing the keys, as expected downstream, and put it in the state
    Composite keys = Composite.newArray()
        .set(Const.FIRST_KEY, Arrays.copyOfRange(keyMaterial, 0, sekSize))
        .set(Const.SECOND_KEY, Arrays.copyOfRange(keyMaterial, sekSize, sekSize + svkSize));
    state.set(Const.SECOND_KEY, keys);

    // CTR modes need specialized IV information
    if (cipherSuite.equals(Const.AES128_CTR_HMAC256_ALG_NAME)
          || cipherSuite.equals(Const.AES256_CTR_HMAC384_ALG_NAME)) {

      state.set(Const.THIRD_KEY, getCtrIv());
      state.set(Const.FOURTH_KEY, 0L);
    }

    return state;
  }

  /**
   * Gets a UEID from a device guid.
   *
   * @param guid The device guid.
   * @return A COSE UEID.
   */
  public byte[] getUeidFromGuid(byte[] guid) {
    ByteBuffer buf = ByteBuffer.allocate(guid.length + 1);
    buf.put((byte) Const.EAT_RAND);
    buf.put(guid);
    buf.flip();
    return Composite.unwrap(buf);
  }

  /**
   * Gets the device guid from a COSE UEID.
   *
   * @param ueid the cose UEID.
   * @return The device GUID as a UUID.
   */
  public UUID getGuidFromUeid(byte[] ueid) {

    if (ueid.length != Const.GUID_SIZE + 1) {
      throw new InvalidMessageException();
    }
    if (ueid[0] != Const.EAT_RAND) {
      throw new InvalidMessageException();
    }

    byte[] guid = new byte[Const.GUID_SIZE];
    System.arraycopy(ueid, 1, guid, 0, guid.length);

    return Composite.newArray()
        .set(Const.FIRST_KEY, guid)
        .getAsUuid(Const.FIRST_KEY);
  }

  /**
   * Gets the device public key from the voucher.
   *
   * @param voucher An ownership voucher.
   * @return The device public key.
   */

  public PublicKey getDevicePublicKey(Composite voucher) {
    Object chain = voucher.get(Const.OV_DEV_CERT_CHAIN);
    if (chain != null) {
      Composite certs = Composite.fromObject(chain);
      if (certs.size() == 0) {
        return null; // no cert chain so most likely a MAROE EPID device
      }
      try {
        CertPath path = getCertPath(certs);
        return path.getCertificates().get(0).getPublicKey();
      } catch (CertificateException e) {
        throw new DispatchException(e);
      }
    }
    return null;
  }

  /**
   * Gets the public key from the voucher.
   *
   * @param voucher A ownership voucher.
   * @return The last owners public key.
   */
  public Composite getOwnerPublicKey(Composite voucher) {
    Composite header = voucher.getAsComposite(Const.OV_HEADER);
    Composite pub = header.getAsComposite(Const.OVH_PUB_KEY);
    Composite entries = voucher.getAsComposite(Const.OV_ENTRIES);
    //can be zero
    if (entries.size() > 0) {
      Composite entry = entries.getAsComposite(entries.size() - 1);
      Composite payload = Composite.fromObject(entry.getAsBytes(Const.COSE_SIGN1_PAYLOAD));
      pub = payload.getAsComposite(Const.OVE_PUB_KEY);
    }
    return pub;
  }

  /**
   * Gets the MD5 fingerprint for the public key.
   *
   * @param publicKey The public key.
   * @return The MD5 fingerprint.
   */
  public String getFingerPrint(PublicKey publicKey) {
    Composite encKey = encode(publicKey, Const.PK_ENC_X509);
    byte[] derBytes = encKey.getAsBytes(Const.PK_BODY);
    MessageDigest messageDigest = null;
    try {
      messageDigest = MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoServiceException(e);
    }
    byte[] digest = messageDigest.digest(derBytes);
    return Composite.toString(digest);
  }

}
