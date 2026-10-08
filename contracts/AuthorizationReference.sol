// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

/// @notice Canonical sponsorship digest and paymaster encoding shared with the Go issuer.
library AuthorizationReference {
    string internal constant SPONSORSHIP_TYPE =
        "Sponsorship(bytes32 sponsorshipId,uint64 policyVersion,bytes32 policyHash,address entryPoint,address sender,bytes32 accountCodeHash,uint256 nonce,bytes32 initCodeHash,bytes32 callDataHash,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,uint128 paymasterVerificationGasLimit,uint128 paymasterPostOpGasLimit,uint256 maxSponsorCostWei,uint48 validAfter,uint48 validUntil)";
    bytes32 internal constant TYPE_HASH = keccak256(bytes(SPONSORSHIP_TYPE));
    bytes32 internal constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes8 internal constant SIGNATURE_MAGIC = 0x22e325a297439656;
    uint256 internal constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct Sponsorship {
        bytes32 sponsorshipId;
        uint64 policyVersion;
        bytes32 policyHash;
        address entryPoint;
        address sender;
        bytes32 accountCodeHash;
        uint256 nonce;
        bytes32 initCodeHash;
        bytes32 callDataHash;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        uint128 paymasterVerificationGasLimit;
        uint128 paymasterPostOpGasLimit;
        uint256 maxSponsorCostWei;
        uint48 validAfter;
        uint48 validUntil;
    }

    function domainSeparator(uint256 chainId, address paymaster) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(DOMAIN_TYPE_HASH, keccak256("GaslessPolicyEngine"), keccak256("1"), chainId, paymaster)
            );
    }

    function structHash(Sponsorship memory a) internal pure returns (bytes32) {
        bytes32[18] memory words;
        words[0] = TYPE_HASH;
        words[1] = a.sponsorshipId;
        words[2] = bytes32(uint256(a.policyVersion));
        words[3] = a.policyHash;
        words[4] = bytes32(uint256(uint160(a.entryPoint)));
        words[5] = bytes32(uint256(uint160(a.sender)));
        words[6] = a.accountCodeHash;
        words[7] = bytes32(a.nonce);
        words[8] = a.initCodeHash;
        words[9] = a.callDataHash;
        words[10] = a.accountGasLimits;
        words[11] = bytes32(a.preVerificationGas);
        words[12] = a.gasFees;
        words[13] = bytes32(uint256(a.paymasterVerificationGasLimit));
        words[14] = bytes32(uint256(a.paymasterPostOpGasLimit));
        words[15] = bytes32(a.maxSponsorCostWei);
        words[16] = bytes32(uint256(a.validAfter));
        words[17] = bytes32(uint256(a.validUntil));
        return keccak256(abi.encode(words));
    }

    function digest(uint256 chainId, address paymaster, Sponsorship memory a) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(chainId, paymaster), structHash(a)));
    }

    function paymasterData(Sponsorship memory a) internal pure returns (bytes memory) {
        return abi.encodePacked(
            a.sponsorshipId, a.policyVersion, a.policyHash, a.maxSponsorCostWei, a.validAfter, a.validUntil
        );
    }

    function paymasterAndData(address paymaster, Sponsorship memory a, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        require(signature.length == 65, "signature length");
        return abi.encodePacked(
            paymaster,
            a.paymasterVerificationGasLimit,
            a.paymasterPostOpGasLimit,
            paymasterData(a),
            signature,
            uint16(65),
            SIGNATURE_MAGIC
        );
    }

    function verify(bytes32 hash, bytes memory signature, address expected) internal pure returns (bool) {
        if (signature.length != 65 || expected == address(0)) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v != 27 && v != 28 || uint256(s) == 0 || uint256(s) > HALF_ORDER || r == bytes32(0)) return false;
        return ecrecover(hash, v, r, s) == expected;
    }
}
