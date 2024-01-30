import { babyjubjub } from "../src/babyJubjub";

describe("testing key & signature generation", () => {
  test("should correctly generate different keypair", () => {
    const keyPair = babyjubjub.ec.genKeyPair();
    const keyPair2 = babyjubjub.ec.genKeyPair();

    expect(keyPair.getPublic()).not.toEqual(keyPair2.getPublic());
  });

  test("should correctly serialize and deserialize", () => {
    const keyPair = babyjubjub.ec.genKeyPair();

    const verifyingKey = keyPair.getPublic();
    const signingKey = keyPair.getPrivate();

    const verifyingKeySerialized = verifyingKey.encode("hex");
    const signingKeySerialized = signingKey.toString("hex");
    expect(typeof verifyingKeySerialized).toEqual("string");
    expect(typeof signingKeySerialized).toEqual("string");

    const verifyingKeyDeserialized = babyjubjub.ec.keyFromPublic(
      verifyingKeySerialized,
      "hex"
    );
    const signingKeyDeserialized = babyjubjub.ec.keyFromPrivate(
      signingKeySerialized,
      "hex"
    );

    expect(verifyingKeyDeserialized.getPublic().encode("hex")).toEqual(
      verifyingKey.encode("hex")
    );
    expect(signingKeyDeserialized.getPrivate().toString("hex")).toEqual(
      signingKey.toString("hex")
    );
  });

  test("should correctly sign and verify", () => {
    const keyPair = babyjubjub.ec.genKeyPair();

    // const verifyingKey = keyPair.getPublic();
    // const signingKey = keyPair.getPrivate();

    const msg = "hello world";
    const msgHash = BigInt(
      "0x" + babyjubjub.ec.hash().update(msg).digest("hex")
    );

    const signature = keyPair.sign(msgHash.toString(16), "hex", {
      canonical: true,
    });

    expect(keyPair.verify(msgHash.toString(16), signature)).toEqual(true);
  });

  test("should correctly sign and verify with serialized", () => {
    const keyPair = babyjubjub.ec.genKeyPair();

    const verifyingKey = keyPair.getPublic();
    const signingKey = keyPair.getPrivate();

    const verifyingKeySerialized = verifyingKey.encode("hex");
    const signingKeySerialized = signingKey.toString("hex");

    const verifyingKeyDeserialized = babyjubjub.ec.keyFromPublic(
      verifyingKeySerialized,
      "hex"
    );
    const signingKeyDeserialized = babyjubjub.ec.keyFromPrivate(
      signingKeySerialized,
      "hex"
    );

    const msg = "a longer test message";
    const msgHash = BigInt(
      "0x" + babyjubjub.ec.hash().update(msg).digest("hex")
    );

    const signature = signingKeyDeserialized.sign(msgHash.toString(16), "hex", {
      canonical: true,
    });
    const signatureDER = signature.toDER();
    const signatureDERSerialized = Buffer.from(signatureDER).toString("base64");
    const signatureDERDeserialized = Buffer.from(
      signatureDERSerialized,
      "base64"
    );

    expect(
      verifyingKeyDeserialized.verify(
        msgHash.toString(16),
        signatureDERDeserialized
      )
    ).toEqual(true);
  });
});
