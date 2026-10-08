// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {BaseAccount} from "@account-abstraction/contracts/core/BaseAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "@account-abstraction/contracts/core/Helpers.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract DemoAccount is BaseAccount {
    IEntryPoint private immutable _entryPoint;
    address public immutable owner;

    constructor(IEntryPoint entryPoint_, address owner_) {
        require(address(entryPoint_) != address(0) && owner_ != address(0), "zero account authority");
        _entryPoint = entryPoint_;
        owner = owner_;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        (address recovered, ECDSA.RecoverError recoverErr,) = ECDSA.tryRecoverCalldata(userOpHash, userOp.signature);
        return
            recoverErr == ECDSA.RecoverError.NoError && recovered == owner
                ? SIG_VALIDATION_SUCCESS
                : SIG_VALIDATION_FAILED;
    }
}
