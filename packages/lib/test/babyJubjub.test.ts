import { EdwardsPoint, WeierstrassPoint } from "../src/babyJubjub";

describe("baby jubjub curve definition", () => {
  test("should correctly convert between weierstrass and edwards points 0", () => {
    const weierstrassPoint = new WeierstrassPoint(
      BigInt(
        "7383369888919701441480368741745717804236448589785295824485316386504973064784"
      ),
      BigInt(
        "13046769583748125084667126323794391074141340611556711664428099286902963678262"
      )
    );

    const edwardsPoint = new EdwardsPoint(
      BigInt(
        "11513997017404587999039986937421722453331811838930011493225155799998969860257"
      ),
      BigInt(
        "15702184800053625297652133943476286357553803483146409610785811576616213183541"
      )
    );

    expect(edwardsPoint.toWeierstrass()).toEqual(weierstrassPoint);
    expect(weierstrassPoint.toEdwards()).toEqual(edwardsPoint);
  });

  test("should correctly convert between weierstrass and edwards points 1", () => {
    const weierstrassPoint = new WeierstrassPoint(
      BigInt(
        "1550638659873531806580386405529412890034592767026339892469683203764441447570"
      ),
      BigInt(
        "3639226155103886317372759888111162619708796017936509514763129225302516184493"
      )
    );

    const edwardsPoint = new EdwardsPoint(
      BigInt(
        "11796026433945242671642728009981778919257130899633207712788256867701213124641"
      ),
      BigInt(
        "14123514812924309349601388555201142092835117152213858542018278815110993732603"
      )
    );

    expect(edwardsPoint.toWeierstrass()).toEqual(weierstrassPoint);
    expect(weierstrassPoint.toEdwards()).toEqual(edwardsPoint);
  });

  test("should correctly convert between weierstrass and edwards points 2", () => {
    const weierstrassPoint = new WeierstrassPoint(BigInt("0"), BigInt("0"));

    const edwardsPoint = new EdwardsPoint(BigInt("0"), BigInt("1"));

    expect(edwardsPoint.toWeierstrass()).toEqual(weierstrassPoint);
    expect(weierstrassPoint.toEdwards()).toEqual(edwardsPoint);
  });

  test("should correctly convert between weierstrass and edwards points 3", () => {
    const weierstrassPoint = new WeierstrassPoint(
      BigInt(
        "4561812309240861642917635986636818826442846353062159251237759819544681210360"
      ),
      BigInt(
        "4047434573331865975122957359703219020835673338643881982088616311845542612717"
      )
    );

    const edwardsPoint = new EdwardsPoint(
      BigInt(
        "11049791236506940775725016544774320801686704107093911375737399460678915074436"
      ),
      BigInt(
        "14122061015030538160275787174689078850141853547608413074819581224165574773574"
      )
    );

    expect(edwardsPoint.toWeierstrass()).toEqual(weierstrassPoint);
    expect(weierstrassPoint.toEdwards()).toEqual(edwardsPoint);
  });
});
