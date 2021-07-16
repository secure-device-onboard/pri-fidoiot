package org.fidoalliance.fdo.protocol;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.HeaderKeys;
import COSE.Message;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.stream.Stream;
import org.fidoalliance.fdo.protocol.ondie.OnDieService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class SignatureTest {

  static byte[] content = "The quick brown fox jumped over the lazy dogs"
      .getBytes(StandardCharsets.UTF_8);

  static Stream<Arguments> ecdsaTestArgProvider() {
    return Stream.of(
        arguments(AlgorithmID.ECDSA_256, Const.COSE_ES256, "secp256r1"),
        arguments(AlgorithmID.ECDSA_384, Const.COSE_ES384, "secp384r1")
    );
  }

  @ParameterizedTest
  @MethodSource("ecdsaTestArgProvider")
  void testEcdsa(AlgorithmID algorithmID, int algorithm, String name) throws Exception {

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec(name));
    KeyPair keys = kpg.generateKeyPair();

    // Sign content with COSE-WG reference encoder...
    OneKey oneKey = new OneKey(keys.getPublic(), keys.getPrivate());
    Sign1Message s1 = new Sign1Message(false);
    s1.addAttribute(HeaderKeys.Algorithm, algorithmID.AsCBOR(), Attribute.PROTECTED);
    s1.SetContent(content);
    s1.sign(oneKey);

    // Sign content with our encoder...
    CryptoService cs = new CryptoService();
    Composite c = cs.sign(keys.getPrivate(), content, algorithm);

    // ..and each should be verifiable by the other.
    Sign1Message s2 = (Sign1Message) Message.DecodeFromBytes(c.toBytes(), MessageTag.Sign1);
    boolean b = s2.validate(oneKey);
    assertTrue(b);

    b = cs.verify(
        keys.getPublic(),
        Composite.fromObject(s1.EncodeToBytes()),
        null,
        null,
        null);
    assertTrue(b);

    // ...a change in the bitstream should make both decoders fail
    byte [] cbor = s1.EncodeToBytes();
    ++cbor[16];

    Sign1Message s3 = (Sign1Message) Message.DecodeFromBytes(cbor, MessageTag.Sign1);
    b = s3.validate(oneKey);
    assertFalse(b);

    b = cs.verify(
        keys.getPublic(),
        Composite.fromObject(cbor),
        null,
        null,
        null);
    assertFalse(b);
  }
}