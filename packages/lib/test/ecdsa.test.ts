import { WeierstrassPoint } from "../src/babyJubjub";
import {
  computeTUFromR,
  privateKeyToPublicKey,
  recoverPubKeyIndexFromSignature,
  generateSignatureKeyPair,
  sign,
  verify,
} from "../src/ecdsa";
import { hexToBigInt, publicKeyFromString } from "../src/utils";
import { getCounterMessage } from "../src/libhalo";

// Tests BabyJubjub ECDSA signature verification in Javascript
describe("javascript signature verification", () => {
  test("should generate different keypairs", () => {
    const keyPair = generateSignatureKeyPair();
    const keyPair2 = generateSignatureKeyPair();

    expect(keyPair.verifyingKey).not.toEqual(keyPair2.verifyingKey);
    expect(keyPair.signingKey).not.toEqual(keyPair2.signingKey);
  });

  test("should correctly sign and verify", () => {
    const keyPair = generateSignatureKeyPair();
    const msg = "hello world";
    const signature = sign(keyPair.signingKey, msg);
    expect(verify(keyPair.verifyingKey, msg, signature)).toEqual(true);
  });

  test("should correctly not verify with different keypair", () => {
    const keyPair = generateSignatureKeyPair();
    const keyPair2 = generateSignatureKeyPair();
    const msg = "hello world";
    const signature = sign(keyPair.signingKey, msg);
    expect(verify(keyPair2.verifyingKey, msg, signature)).toEqual(false);
  });

  test("should correctly not verify with different message", () => {
    const keyPair = generateSignatureKeyPair();
    const msg = "hello world";
    const msg2 = "hello world2";
    const signature = sign(keyPair.signingKey, msg);
    expect(verify(keyPair.verifyingKey, msg2, signature)).toEqual(false);
  });

  test("should correctly verify libhalo sig 1", () => {
    const msg = getCounterMessage(
      12,
      "2ECE8845C4114D80DCCF8E911E2FD586BF9E1106650F8B55C0AC55D6"
    );
    const verifyingKey =
      "0407258C81D3DE9F17FFADFCD8CE1CBCAD83027A7FD0A3221FF03CFD1DFBE0CDDE04D68FC27A9F3F0A0BF480326CE5DCD2A9CBFCA34D4098E6A60DA4AE64281950";
    const derSig =
      "30440220041AA41A2D8E6384EE5DF70CC0AD6713F9236C9C97E222939B73D9673377FD6C0220015F084155ABC57BA4176C1F39A0952F47110C45D78387AF5603529D58C7CB960407";

    expect(verify(verifyingKey, msg, derSig)).toEqual(true);
  });

  test("should correctly verify libhalo sig 2", () => {
    const msg = getCounterMessage(
      13,
      "F8D06C26B7FE3598D827D6B91535766B1F4909B8B9174E60A63EE6E6"
    );
    const verifyingKey =
      "0407258C81D3DE9F17FFADFCD8CE1CBCAD83027A7FD0A3221FF03CFD1DFBE0CDDE04D68FC27A9F3F0A0BF480326CE5DCD2A9CBFCA34D4098E6A60DA4AE64281950";
    const derSig =
      "3044022005DBAA155224C52E2B9CBB965D07E25AFF7E4A0589DFEECA55F0DD34035A4B9F0220045B9D859FEADA70F9015CB60C57E5BD6CCC6F705BBC7471B522C18C4949FA8E0407";

    expect(verify(verifyingKey, msg, derSig)).toEqual(true);
  });

  test("should correctly verify libhalo sig 3", () => {
    const msg = getCounterMessage(
      14,
      "17B86CC70F389D4C5BFA44B871F16BCC76521201DF1A69FC10DCE9A6"
    );
    const verifyingKey =
      "0407258C81D3DE9F17FFADFCD8CE1CBCAD83027A7FD0A3221FF03CFD1DFBE0CDDE04D68FC27A9F3F0A0BF480326CE5DCD2A9CBFCA34D4098E6A60DA4AE64281950";
    const derSig =
      "30440220020CF4AA0C8A2EE10C41016A6069E3604B1F8487C8C6EE95954F5E15E00128200220041576E3149B4CCA5F281B56122100877BEBCDD3F8338DCD574CBC1447CFB3E60407";

    expect(verify(verifyingKey, msg, derSig)).toEqual(true);
  });

  test("should correctly verify libhalo sig 4", () => {
    const msg = getCounterMessage(
      2,
      "23BA6C027D8980C0F6F72D1F91660FA57D7C09D7DBEA000BF4727842"
    );
    const verifyingKey =
      "040902129E2195B5DEDC2F9B060E846CE6FF6B6A32794A5BA22F3FA03B068F90A52635451C65448273303F2D403F92FF57FD10A67B1B956B3258A1AA5F4F88B5CB";
    const derSig =
      "3044022005B723A4E98840B387A3FE33A2F6C31E746CC00C4E8B260AF6BC8D014C11462B02200287CBFF41C066D3094CBD33C7F03594BD87298FC80B739B5D0F245F530F30060409";

    expect(verify(verifyingKey, msg, derSig)).toEqual(true);
  });

  test("should correctly verify libhalo sig 5", () => {
    const msg = getCounterMessage(
      3,
      "CB62FA3C9E5772DEDE937C0CB63006118D7F90FEDC73DB84F626796A"
    );
    const verifyingKey =
      "040902129E2195B5DEDC2F9B060E846CE6FF6B6A32794A5BA22F3FA03B068F90A52635451C65448273303F2D403F92FF57FD10A67B1B956B3258A1AA5F4F88B5CB";
    const derSig =
      "3044022005B66AFC1CC0ECFAEA261F03E4561AC2ACCC848EA20091344A6782620335FE1402200213C98E5FED563603A545163229274E86A646176ACF18C75361764B884E92940409";

    expect(verify(verifyingKey, msg, derSig)).toEqual(true);
  });
});

// Tests BabyJubjub ECDSA public key recovery in Javascript
describe("ecdsa public key recovery", () => {
  it("should recover the correct public key index", () => {
    const pubKeys = [
      "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
      "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
    ];
    const msgHash = BigInt("0");
    const sig = {
      r: hexToBigInt(
        "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
      ),
      s: hexToBigInt(
        "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
      ),
    };

    const pubKeyPoints = pubKeys.map((pubKey) => publicKeyFromString(pubKey));

    const recoveredIndex = recoverPubKeyIndexFromSignature(
      sig,
      msgHash,
      pubKeyPoints
    );

    const expectedIndex = 2;

    expect(recoveredIndex).toEqual(expectedIndex);
  });

  it("should error if the public key is not in the list", () => {
    const pubKeys = [
      "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
      "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
    ];
    const msgHash = BigInt("0");
    const sig = {
      r: hexToBigInt(
        "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B5"
      ),
      s: hexToBigInt(
        "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
      ),
    };

    const pubKeyPoints = pubKeys.map((pubKey) => publicKeyFromString(pubKey));

    expect(() =>
      recoverPubKeyIndexFromSignature(sig, msgHash, pubKeyPoints)
    ).toThrow();
  });

  it("should error if public key is not recoverable", () => {
    const pubKeys = [
      "041941f5abe4f903af965d707182b688bd1fa725fd2cbc648fc435feb42a3794593275a2e9b4ad4bc0d2f3ecc8d23e3cf89da889d7aa35ce33f132d87b5bb5c393",
      "049ae9f2ec6a4db43f0e081a436f885b0d3f5753a45b00d2f2e3da38956848c4ff0205d89e14a2e36976bfe033407dbce6b48261d84d201277de0c3b82f08ddb09",
      "041052d6da0c3d7248e39e08912e2daa53c4e54cd9f2d96e3702fa15e77b199a501cd835bbddcc77134dc59dbbde2aa702183a68c90877906a31536eef972fac36",
      "044d9d03f3266f24777ac488f04ec579e1c4bea984398c9b98d99a9e31bc75ef0f13a19471a7297a6f2bf0126ed93d4c55b6e98ec286203e3d761c61922e3a4cda",
    ];
    const msgHash = BigInt("0");
    const sig = {
      r: hexToBigInt(
        "00EF7145470CEC0B683C629CBA8ED58110000FFE657366F7D5A91F2D149DD8B4"
      ),
      s: hexToBigInt(
        "0370C60A23266F520C56DA088B4C4AFAAAF6BB1993A501980F6D8FB6F343984A"
      ),
    };

    const pubKeyPoints = pubKeys.map((pubKey) => publicKeyFromString(pubKey));

    expect(() =>
      recoverPubKeyIndexFromSignature(sig, msgHash, pubKeyPoints)
    ).toThrow();
  });
});

// Tests conversion between ECDSA private keys and public keys
describe("private to public key conversion", () => {
  test("should convert a private key to a public key 0", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    const expectedPubKey = new WeierstrassPoint(
      BigInt(
        "7383369888919701441480368741745717804236448589785295824485316386504973064784"
      ),
      BigInt(
        "13046769583748125084667126323794391074141340611556711664428099286902963678262"
      )
    );

    expect(pubKey).toEqual(expectedPubKey);
  });

  test("should convert a private key to a public key 1", () => {
    const privKey =
      "04b81e7180cd9504ce1bf0f728b4c828ad369781986aff07284d60ec1d59850b";
    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    const expectedPubKey = new WeierstrassPoint(
      BigInt(
        "8022836036792728510020073593790625374591718668941094754729876067757770684825"
      ),
      BigInt(
        "2888043282838146526405156459340757249954671046314727413645487686643973993965"
      )
    );

    expect(pubKey).toEqual(expectedPubKey);
  });

  test("should convert a private key to a public key 2", () => {
    const privKey =
      "02ea6ba4d6ec9b1b724f93a5ddf4ddcc94fc09909753088c272970fe3c99c4d8";
    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    const expectedPubKey = new WeierstrassPoint(
      BigInt(
        "9714024128310316092057230443118059995407288196097449837364797009977227758081"
      ),
      BigInt(
        "3986000760809817233522229217388333078261970153215912556094459527204210942908"
      )
    );

    expect(pubKey).toEqual(expectedPubKey);
  });

  test("should convert a private key to a public key 3", () => {
    const privKey =
      "0323dbbda9a5aff570d974d71c88334cf99ab9c0455e1d2546ca03ca069eb1e0";
    const pubKey = privateKeyToPublicKey(hexToBigInt(privKey));

    const expectedPubKey = new WeierstrassPoint(
      BigInt(
        "7383369888919701441480368741745717804236448589785295824485316386504973064784"
      ),
      BigInt(
        "13046769583748125084667126323794391074141340611556711664428099286902963678262"
      )
    );

    expect(pubKey).toEqual(expectedPubKey);
  });
});

// These examples are taken from the BabyJubjub ECDSA Python implementation
describe("efficient ecdsa utils", () => {
  test("should convert R and a message hash to T and U correctly", () => {
    const R = new WeierstrassPoint(
      BigInt(
        "10670285876735019599106866976684908952274911389930362762537090111564921097016"
      ),
      BigInt(
        "9160051989315312112039929478094450530265103887834999493414216896339841057063"
      )
    );
    const msgHash = BigInt("2");

    const expectedT = new WeierstrassPoint(
      BigInt(
        "6952765017569839958343264710546584578753992328892854973252223160184157850745"
      ),
      BigInt(
        "9563206295407598382073804946882877811714977803488938527800721542415224962428"
      )
    );
    const expectedU = new WeierstrassPoint(
      BigInt(
        "12614432555643728606782560810226874354451117249983040637892389649426582274947"
      ),
      BigInt(
        "13906431017424053199814642411232056924432788712909729385753697397225312690892"
      )
    );

    const { T, U } = computeTUFromR(R.toEdwards(), msgHash);

    expect(T.toWeierstrass().equals(expectedT)).toBe(true);
    expect(U.toWeierstrass().equals(expectedU)).toBe(true);
  });
});
