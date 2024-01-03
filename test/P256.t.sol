// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {P256} from "../src/P256.sol";
import {P256Verifier} from "../src/P256Verifier.sol";
import {P256Sign} from "../src/P256Sign.sol";

contract P256Test is Test {
    uint256[2] public pubKey;

    P256Sign p256signer;

    function setUp() public {
        // Deploy P256 Signer
        p256signer = new P256Sign();
        // Deploy P256 Verifier
        vm.etch(P256.VERIFIER, type(P256Verifier).runtimeCode);
        pubKey = [
            0x65a2fa44daad46eab0278703edb6c4dcf5e30b8a9aec09fdc71a56f52aa392e4,
            0x4a7a9e4604aa36898209997288e902ac544a555e4b5e0a9efef2b59233f3f437
        ];
    }

    function testSigningAgainstVerifier() public {
        uint256 privKey = 123;
        uint256 pubkeyX = 0x811a6c2bd2a547d0dd84747297fec47719e7c3f9b0024f027c2b237be99aac39;
        uint256 pubkeyY = 0xa9230acbd163d0cb1524a0f5ea4bfed6058cec6f18368f72a12aa0c4d083ff64;
        bytes32 hash = 0x267f9ea080b54bbea2443dff8aa543604564329783b6a515c6663a691c555490;
        uint256 k = 3333;
        (uint256 r, uint256 s) = p256signer.ecdsa_sign(
            hash,
            k,
            privKey
        );

        bool res = P256.verifySignature(hash, r, s, pubkeyX, pubkeyY);
        assertEq(res, true);
    }

    function testSigningAgainstExternalSignature() public {
        uint256 expected_r = 0xa13acb6c7be08c4bee140320ad750189f74e15c3142f55bcb5c7e3087b83550a;
        uint256 expected_s = 0x1d552ab4459b326c9fc68871e94cb808aea07b9fd74e585d058cf24a0924a5d9;

        bytes32 hash = 0x6c60199eb5930834eb3b627742170983b150bde46bca7957d1dd0f767fe3acbb;

        uint256 privKey = uint256(0x97ddae0f3a25b92268175400149d75d6887b9cefaf28ea2c078e05cdc15a3c0a);

        uint256 k = 0x447eabff81d68f79e6446d794cca4f594e3afcd99a42590f717faad1d4e15926;
        (uint256 r, uint256 s) = p256signer.ecdsa_sign(
            hash,
            k,
            privKey
        );
        assertEq(r, expected_r);
        assertEq(s, expected_s);
    }

    function testMalleable() public {
        // Malleable signature. s is > n/2
        uint256 r = 0x01655c1753db6b61a9717e4ccc5d6c4bf7681623dd54c2d6babc55125756661c;
        uint256 s = 0xf073023b6de130f18510af41f64f067c39adccd59f8789a55dbbe822b0ea2317;

        bytes32 hash = 0x267f9ea080b54bbea2443dff8aa543604564329783b6a515c6663a691c555490;

        bool res = P256.verifySignatureAllowMalleability(
            hash,
            r,
            s,
            pubKey[0],
            pubKey[1]
        );
        assertEq(res, true);

        res = P256.verifySignature(hash, r, s, pubKey[0], pubKey[1]);
        assertEq(res, false);
    }

    function testNonMalleable() public {
        // Non-malleable signature. s is <= n/2
        uint256 r = 0x01655c1753db6b61a9717e4ccc5d6c4bf7681623dd54c2d6babc55125756661c;
        uint256 s = 7033802732221576339889804108463427183539365869906989872244893535944704590394;

        bytes32 hash = 0x267f9ea080b54bbea2443dff8aa543604564329783b6a515c6663a691c555490;

        bool res = P256.verifySignatureAllowMalleability(
            hash,
            r,
            s,
            pubKey[0],
            pubKey[1]
        );
        assertEq(res, true);

        res = P256.verifySignature(hash, r, s, pubKey[0], pubKey[1]);
        assertEq(res, true);
    }
}
