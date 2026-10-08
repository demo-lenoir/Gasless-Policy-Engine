// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {BasePaymaster} from "@account-abstraction/contracts/core/BasePaymaster.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {_packValidationData} from "@account-abstraction/contracts/core/Helpers.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {AuthorizationReference} from "./AuthorizationReference.sol";

contract PolicyPaymaster is BasePaymaster, Pausable {
    uint256 public constant PAYMASTER_DATA_LENGTH = 116;
    uint256 public constant PAYMASTER_AND_DATA_LENGTH = 243;

    address public immutable authorizationSigner;
    bytes32 public immutable accountCodeHash;

    event SponsorshipValidated(bytes32 indexed sponsorshipId, bytes32 indexed userOpHash, uint256 maxCost);

    error InvalidAuthorizationData();

    constructor(IEntryPoint entryPoint_, address owner_, address signer_, bytes32 accountCodeHash_)
        BasePaymaster(entryPoint_, owner_)
    {
        require(signer_ != address(0) && accountCodeHash_ != bytes32(0), "zero authorization identity");
        authorizationSigner = signer_;
        accountCodeHash = accountCodeHash_;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        override
        whenNotPaused
        returns (bytes memory context, uint256 validationData)
    {
        bytes calldata encoded = userOp.paymasterAndData;
        if (
            encoded.length != PAYMASTER_AND_DATA_LENGTH || address(bytes20(encoded[0:20])) != address(this)
                || bytes2(encoded[233:235]) != bytes2(uint16(65))
                || bytes8(encoded[235:243]) != AuthorizationReference.SIGNATURE_MAGIC
        ) {
            revert InvalidAuthorizationData();
        }

        AuthorizationReference.Sponsorship memory a;
        a.sponsorshipId = bytes32(encoded[52:84]);
        a.policyVersion = uint64(bytes8(encoded[84:92]));
        a.policyHash = bytes32(encoded[92:124]);
        a.maxSponsorCostWei = uint256(bytes32(encoded[124:156]));
        a.validAfter = uint48(bytes6(encoded[156:162]));
        a.validUntil = uint48(bytes6(encoded[162:168]));
        a.paymasterVerificationGasLimit = uint128(bytes16(encoded[20:36]));
        a.paymasterPostOpGasLimit = uint128(bytes16(encoded[36:52]));

        if (
            a.sponsorshipId == bytes32(0) || a.policyVersion == 0 || a.policyHash == bytes32(0) || a.validAfter == 0
                || a.validUntil <= a.validAfter || a.validUntil >= (1 << 47) || a.paymasterVerificationGasLimit == 0
                || a.paymasterPostOpGasLimit != 0 || userOp.initCode.length != 0
                || userOp.sender.codehash != accountCodeHash || maxCost > a.maxSponsorCostWei
        ) {
            revert InvalidAuthorizationData();
        }

        a.entryPoint = address(entryPoint());
        a.sender = userOp.sender;
        a.accountCodeHash = accountCodeHash;
        a.nonce = userOp.nonce;
        a.initCodeHash = keccak256(userOp.initCode);
        a.callDataHash = keccak256(userOp.callData);
        a.accountGasLimits = userOp.accountGasLimits;
        a.preVerificationGas = userOp.preVerificationGas;
        a.gasFees = userOp.gasFees;

        bytes32 digest = AuthorizationReference.digest(block.chainid, address(this), a);
        (address recovered, ECDSA.RecoverError recoverErr,) = ECDSA.tryRecoverCalldata(digest, encoded[168:233]);
        bool invalidSignature = recoverErr != ECDSA.RecoverError.NoError || recovered != authorizationSigner;
        validationData = _packValidationData(invalidSignature, a.validUntil, a.validAfter);
        if (!invalidSignature) {
            emit SponsorshipValidated(a.sponsorshipId, userOpHash, maxCost);
        }
        return ("", validationData);
    }
}
