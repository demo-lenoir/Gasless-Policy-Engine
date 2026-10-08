// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import "../AuthorizationReference.sol";

interface VmReference {
    function readFile(string calldata path) external returns (string memory);
    function parseJsonString(string calldata json, string calldata key) external pure returns (string memory);
    function parseJsonUint(string calldata json, string calldata key) external pure returns (uint256);
    function parseJsonAddress(string calldata json, string calldata key) external pure returns (address);
    function parseBytes32(string calldata value) external pure returns (bytes32);
    function parseBytes(string calldata value) external pure returns (bytes memory);
    function parseUint(string calldata value) external pure returns (uint256);
}

contract AuthorizationReferenceTest {
    VmReference private constant vm = VmReference(address(uint160(uint256(keccak256("hevm cheat code")))));

    function textValue(string memory json, string memory key) internal pure returns (string memory) {
        return vm.parseJsonString(json, string.concat(".", key));
    }

    function hashValue(string memory json, string memory key) internal pure returns (bytes32) {
        return vm.parseBytes32(textValue(json, key));
    }

    function numeric(string memory json, string memory key) internal pure returns (uint256) {
        return vm.parseUint(textValue(json, key));
    }

    function fixture(string memory json) internal pure returns (AuthorizationReference.Sponsorship memory a) {
        a.sponsorshipId = hashValue(json, "sponsorship_id");
        a.policyVersion = uint64(vm.parseJsonUint(json, ".policy_version"));
        a.policyHash = hashValue(json, "policy_hash");
        a.entryPoint = vm.parseJsonAddress(json, ".entry_point");
        a.sender = vm.parseJsonAddress(json, ".sender");
        a.accountCodeHash = hashValue(json, "account_code_hash");
        a.nonce = numeric(json, "nonce");
        a.initCodeHash = hashValue(json, "init_code_hash");
        a.callDataHash = hashValue(json, "call_data_hash");
        a.accountGasLimits = hashValue(json, "account_gas_limits");
        a.preVerificationGas = numeric(json, "pre_verification_gas");
        a.gasFees = hashValue(json, "gas_fees");
        a.paymasterVerificationGasLimit = uint128(numeric(json, "paymaster_verification_gas"));
        a.paymasterPostOpGasLimit = uint128(numeric(json, "paymaster_postop_gas"));
        a.maxSponsorCostWei = numeric(json, "max_sponsor_cost_wei");
        a.validAfter = uint48(vm.parseJsonUint(json, ".valid_after"));
        a.validUntil = uint48(vm.parseJsonUint(json, ".valid_until"));
    }

    function testCommittedVector() public {
        string memory json = vm.readFile("testdata/authorization-vector.json");
        AuthorizationReference.Sponsorship memory a = fixture(json);
        uint256 chainId = numeric(json, "chain_id");
        address paymaster = vm.parseJsonAddress(json, ".paymaster");
        bytes32 digest = AuthorizationReference.digest(chainId, paymaster, a);
        require(
            AuthorizationReference.domainSeparator(chainId, paymaster) == hashValue(json, "domain_separator"),
            "domain mismatch"
        );
        require(AuthorizationReference.structHash(a) == hashValue(json, "struct_hash"), "struct mismatch");
        require(digest == hashValue(json, "digest"), "digest mismatch");
        bytes memory signature = vm.parseBytes(textValue(json, "signature"));
        require(
            AuthorizationReference.verify(digest, signature, vm.parseJsonAddress(json, ".expected_signer")),
            "signature mismatch"
        );
        require(
            keccak256(AuthorizationReference.paymasterData(a))
                == keccak256(vm.parseBytes(textValue(json, "paymaster_data"))),
            "data mismatch"
        );
        require(
            keccak256(AuthorizationReference.paymasterAndData(paymaster, a, signature))
                == keccak256(vm.parseBytes(textValue(json, "paymaster_and_data"))),
            "encoding mismatch"
        );
    }

    function testDomainAndSignedFieldMutations() public {
        string memory json = vm.readFile("testdata/authorization-vector.json");
        AuthorizationReference.Sponsorship memory a = fixture(json);
        address paymaster = vm.parseJsonAddress(json, ".paymaster");
        address signer = vm.parseJsonAddress(json, ".expected_signer");
        bytes memory signature = vm.parseBytes(textValue(json, "signature"));
        bytes32 expected = hashValue(json, "digest");
        require(
            !AuthorizationReference.verify(AuthorizationReference.digest(31338, paymaster, a), signature, signer),
            "chain mutation"
        );
        require(
            !AuthorizationReference.verify(AuthorizationReference.digest(31337, address(0x4444), a), signature, signer),
            "paymaster mutation"
        );
        a.entryPoint = address(0x4444);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.sender = address(0x4444);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.nonce++;
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.callDataHash = bytes32(uint256(a.callDataHash) ^ 1);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.accountGasLimits = bytes32(uint256(a.accountGasLimits) ^ 1);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.accountGasLimits = bytes32(uint256(a.accountGasLimits) ^ (uint256(1) << 128));
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.gasFees = bytes32(uint256(a.gasFees) ^ 1);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.gasFees = bytes32(uint256(a.gasFees) ^ (uint256(1) << 128));
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.accountCodeHash = bytes32(uint256(a.accountCodeHash) ^ 1);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.initCodeHash = bytes32(uint256(a.initCodeHash) ^ 1);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.maxSponsorCostWei++;
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.paymasterVerificationGasLimit++;
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.paymasterPostOpGasLimit++;
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.preVerificationGas++;
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.policyVersion++;
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.policyHash = bytes32(uint256(a.policyHash) ^ 1);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.sponsorshipId = bytes32(uint256(a.sponsorshipId) ^ 1);
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.validAfter++;
        _mustFail(a, paymaster, signer, signature, expected);
        a = fixture(json);
        a.validUntil++;
        _mustFail(a, paymaster, signer, signature, expected);
    }

    function testSignatureAndSchemaVersionRejection() public {
        string memory json = vm.readFile("testdata/authorization-vector.json");
        AuthorizationReference.Sponsorship memory a = fixture(json);
        address paymaster = vm.parseJsonAddress(json, ".paymaster");
        address signer = vm.parseJsonAddress(json, ".expected_signer");
        bytes32 hash = AuthorizationReference.digest(31337, paymaster, a);
        bytes memory signature = vm.parseBytes(textValue(json, "signature"));
        signature[64] = bytes1(uint8(0));
        require(!AuthorizationReference.verify(hash, signature, signer), "wrong recovery byte");
        signature = vm.parseBytes(textValue(json, "signature"));
        for (uint256 i = 32; i < 64; i++) {
            signature[i] = 0xff;
        }
        require(!AuthorizationReference.verify(hash, signature, signer), "high-s signature");
        signature = vm.parseBytes(textValue(json, "signature"));
        require(!AuthorizationReference.verify(hash, signature, address(0x4444)), "wrong signer");
        bytes32 changedDomain = keccak256(
            abi.encode(
                AuthorizationReference.DOMAIN_TYPE_HASH,
                keccak256("GaslessPolicyEngine"),
                keccak256("2"),
                uint256(31337),
                paymaster
            )
        );
        require(changedDomain != AuthorizationReference.domainSeparator(31337, paymaster), "schema version");
    }

    function _mustFail(
        AuthorizationReference.Sponsorship memory a,
        address paymaster,
        address signer,
        bytes memory signature,
        bytes32 original
    ) internal pure {
        bytes32 changed = AuthorizationReference.digest(31337, paymaster, a);
        require(changed != original && !AuthorizationReference.verify(changed, signature, signer), "mutation accepted");
    }
}
