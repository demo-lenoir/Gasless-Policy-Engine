// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {AuthorizationReference} from "../AuthorizationReference.sol";
import {PolicyPaymaster} from "../PolicyPaymaster.sol";
import {DemoAccount} from "../DemoAccount.sol";
import {DemoCounter} from "../DemoCounter.sol";

interface VmPaymaster {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function addr(uint256 key) external returns (address);
    function sign(uint256 key, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function chainId(uint256 chainId) external;
    function deal(address who, uint256 amount) external;
    function prank(address sender) external;
    function prank(address sender, address origin) external;
    function expectRevert() external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

contract PolicyPaymasterTest {
    VmPaymaster private constant vm = VmPaymaster(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant SPONSOR_KEY = 1;
    uint256 private constant OWNER_KEY = 2;
    uint256 private constant RELAYER_KEY = 3;

    EntryPoint private entry;
    DemoAccount private account;
    DemoCounter private counter;
    PolicyPaymaster private paymaster;
    address private relayer;

    function setUp() public {
        vm.warp(1_000);
        vm.chainId(31_337);
        vm.deal(address(this), 10 ether);
        entry = new EntryPoint();
        account = new DemoAccount(entry, vm.addr(OWNER_KEY));
        counter = new DemoCounter();
        paymaster = new PolicyPaymaster(entry, address(this), vm.addr(SPONSOR_KEY), address(account).codehash);
        paymaster.deposit{value: 1 ether}();
        relayer = vm.addr(RELAYER_KEY);
        require(address(account).balance == 0, "account funded");
    }

    function sign(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function operation(bytes memory targetCall) internal returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = entry.getNonce(address(account), 0);
        op.initCode = "";
        op.callData = abi.encodeWithSelector(hex"b61d27f6", address(counter), 0, targetCall);
        op.accountGasLimits = bytes32((uint256(300_000) << 128) | 300_000);
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32((uint256(1 gwei) << 128) | 10 gwei);
    }

    function authorize(PackedUserOperation memory op, bytes32 id) internal returns (PackedUserOperation memory) {
        AuthorizationReference.Sponsorship memory a;
        a.sponsorshipId = id;
        a.policyVersion = 1;
        a.policyHash = keccak256("policy snapshot");
        a.entryPoint = address(entry);
        a.sender = op.sender;
        a.accountCodeHash = address(account).codehash;
        a.nonce = op.nonce;
        a.initCodeHash = keccak256(op.initCode);
        a.callDataHash = keccak256(op.callData);
        a.accountGasLimits = op.accountGasLimits;
        a.preVerificationGas = op.preVerificationGas;
        a.gasFees = op.gasFees;
        a.paymasterVerificationGasLimit = 300_000;
        a.paymasterPostOpGasLimit = 0;
        a.maxSponsorCostWei = (300_000 + 300_000 + 50_000 + 300_000) * 10 gwei;
        a.validAfter = 999;
        a.validUntil = 1_100;
        op.paymasterAndData = AuthorizationReference.paymasterAndData(
            address(paymaster),
            a,
            sign(SPONSOR_KEY, AuthorizationReference.digest(block.chainid, address(paymaster), a))
        );
        require(op.paymasterAndData.length == 243, "wrong encoding length");
        op.signature = sign(OWNER_KEY, entry.getUserOpHash(op));
        return op;
    }

    function submit(PackedUserOperation memory op) internal {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(relayer, relayer);
        entry.handleOps(ops, payable(relayer));
    }

    function testDirectEntryPointPaysForZeroBalanceAccount() public {
        PackedUserOperation memory op =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(1)));
        uint256 beforeDeposit = entry.balanceOf(address(paymaster));
        submit(op);
        require(counter.count() == 1, "call did not execute");
        require(address(account).balance == 0, "account paid gas");
        require(entry.balanceOf(address(paymaster)) < beforeDeposit, "deposit unchanged");
        vm.expectRevert();
        submit(op);
        require(counter.count() == 1, "replay executed");
    }

    function testMutationsFailPaymasterValidation() public {
        PackedUserOperation memory original =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(2)));
        PackedUserOperation memory changed = clone(original);
        changed.callData = abi.encodeWithSelector(
            hex"b61d27f6", address(counter), 0, abi.encodeCall(DemoCounter.increment, (bytes32("second")))
        );
        mustReject(changed);
        changed = clone(original);
        changed.callData = abi.encodeWithSelector(
            hex"b61d27f6", address(0x1234), 0, abi.encodeCall(DemoCounter.increment, (bytes32("first")))
        );
        mustReject(changed);
        changed = clone(original);
        changed.callData = abi.encodeWithSelector(
            hex"b61d27f6", address(counter), 1, abi.encodeCall(DemoCounter.increment, (bytes32("first")))
        );
        mustReject(changed);
        changed = clone(original);
        changed.nonce++;
        mustReject(changed);
        changed = clone(original);
        changed.accountGasLimits = bytes32(uint256(changed.accountGasLimits) + 1);
        mustReject(changed);
        changed = clone(original);
        changed.accountGasLimits = bytes32(uint256(changed.accountGasLimits) + (uint256(1) << 128));
        mustReject(changed);
        changed = clone(original);
        changed.preVerificationGas++;
        mustReject(changed);
        changed = clone(original);
        changed.gasFees = bytes32(uint256(changed.gasFees) + 1);
        mustReject(changed);
        changed = clone(original);
        changed.gasFees = bytes32(uint256(changed.gasFees) + (uint256(1) << 128));
        mustReject(changed);
        changed = clone(original);
        changed.paymasterAndData[35] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(original);
        changed.paymasterAndData[83] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(original);
        changed.paymasterAndData[91] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(original);
        changed.paymasterAndData[123] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(original);
        changed.paymasterAndData[161] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(original);
        changed.paymasterAndData[167] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(original);
        changed.initCode = hex"1234";
        mustReject(changed);
    }

    function clone(PackedUserOperation memory op) internal pure returns (PackedUserOperation memory) {
        return abi.decode(abi.encode(op), (PackedUserOperation));
    }

    function mustReject(PackedUserOperation memory op) internal {
        vm.prank(address(entry));
        try paymaster.validatePaymasterUserOp(op, bytes32(uint256(1)), 1) returns (
            bytes memory, uint256 validationData
        ) {
            require(uint160(validationData) == 1, "mutated authorization accepted");
        } catch {
            // Structural rejection is also fail closed.
        }
    }

    function testPauseAndExpiry() public {
        PackedUserOperation memory op =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(3)));
        paymaster.pause();
        vm.expectRevert();
        submit(op);
        paymaster.unpause();
        submit(op);
        require(counter.count() == 1, "unpause did not restore validity");

        PackedUserOperation memory next =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("second")))), bytes32(uint256(4)));
        vm.warp(1_101);
        vm.expectRevert();
        submit(next);
    }

    function testMalformedAndInsufficientDeposit() public {
        PackedUserOperation memory op =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(5)));
        op.paymasterAndData = hex"1234";
        mustReject(op);
        op = authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(5)));
        op.paymasterAndData[242] ^= bytes1(uint8(1));
        mustReject(op);
        op = authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(6)));
        paymaster.withdrawTo(payable(address(this)), entry.balanceOf(address(paymaster)));
        vm.expectRevert();
        submit(op);
    }

    function testDomainAndAccountIdentity() public {
        PackedUserOperation memory op =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(7)));
        vm.chainId(31_338);
        mustReject(op);
        vm.chainId(31_337);

        PolicyPaymaster other =
            new PolicyPaymaster(entry, address(this), vm.addr(SPONSOR_KEY), address(account).codehash);
        PackedUserOperation memory changed = clone(op);
        bytes memory replacement = abi.encodePacked(address(other));
        for (uint256 i; i < 20; ++i) {
            changed.paymasterAndData[i] = replacement[i];
        }
        vm.prank(address(entry));
        (, uint256 validationData) = other.validatePaymasterUserOp(changed, bytes32(uint256(1)), 1);
        require(uint160(validationData) == 1, "different paymaster accepted signature");

        DemoAccount otherAccount = new DemoAccount(entry, vm.addr(OWNER_KEY));
        changed = clone(op);
        changed.sender = address(otherAccount);
        mustReject(changed);
        changed = clone(op);
        changed.paymasterAndData[52] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(op);
        changed.paymasterAndData[84] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(op);
        changed.paymasterAndData[92] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(op);
        changed.paymasterAndData[124] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(op);
        changed.paymasterAndData[156] ^= bytes1(uint8(1));
        mustReject(changed);
        changed = clone(op);
        changed.paymasterAndData[162] ^= bytes1(uint8(1));
        mustReject(changed);
    }

    function testValidityBoundariesAndAccess() public {
        PackedUserOperation memory op =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(8)));
        vm.warp(999);
        vm.expectRevert();
        submit(op);
        vm.warp(1_099);
        submit(op);
        PackedUserOperation memory last =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("last")))), bytes32(uint256(12)));
        vm.warp(1_100);
        submit(last);
        require(counter.count() == 2, "validUntil boundary rejected");
        vm.prank(relayer);
        vm.expectRevert();
        paymaster.pause();
        vm.warp(1_101);
        PackedUserOperation memory next =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("second")))), bytes32(uint256(9)));
        vm.expectRevert();
        submit(next);
    }

    function testExecutionRevertStillChargesPaymaster() public {
        PackedUserOperation memory op = authorize(operation(abi.encodeCall(DemoCounter.fail, ())), bytes32(uint256(10)));
        uint256 beforeDeposit = entry.balanceOf(address(paymaster));
        vm.recordLogs();
        submit(op);
        require(counter.count() == 0, "failed call changed state");
        require(entry.balanceOf(address(paymaster)) < beforeDeposit, "failed execution charged no gas");
        VmPaymaster.Log[] memory logs = vm.getRecordedLogs();
        bytes32 eventTopic = keccak256("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
        bool observed;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(entry) && logs[i].topics[0] == eventTopic) {
                (, bool success, uint256 actualGasCost,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
                require(!success && actualGasCost > 0, "failed operation event incorrect");
                observed = true;
            }
        }
        require(observed, "operation event missing");
    }

    function testMaximumCostBound() public {
        PackedUserOperation memory op =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(13)));
        uint256 cap = abi.decode(slice(op.paymasterAndData, 124, 32), (uint256));
        vm.prank(address(entry));
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(op, bytes32(uint256(1)), cap);
        require(uint160(validationData) == 0, "exact cost cap rejected");
        vm.prank(address(entry));
        bool rejected;
        try paymaster.validatePaymasterUserOp(op, bytes32(uint256(1)), cap + 1) {}
        catch {
            rejected = true;
        }
        require(rejected, "excess cost accepted");
    }

    function testAccountAndPaymasterAuthorizationAreDistinct() public {
        PackedUserOperation memory op =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(14)));
        op.signature = sign(SPONSOR_KEY, entry.getUserOpHash(op));
        vm.expectRevert();
        submit(op);
        vm.expectRevert();
        account.execute(address(counter), 0, abi.encodeCall(DemoCounter.increment, (bytes32("direct"))));
    }

    function slice(bytes memory source, uint256 offset, uint256 length) internal pure returns (bytes memory result) {
        result = new bytes(length);
        for (uint256 i; i < length; ++i) {
            result[i] = source[offset + i];
        }
    }

    function testFuzzMalformedPaymasterLength(uint8 length) public {
        PackedUserOperation memory op =
            authorize(operation(abi.encodeCall(DemoCounter.increment, (bytes32("first")))), bytes32(uint256(11)));
        if (length == 243) return;
        bytes memory payload = new bytes(length);
        uint256 copyLength = length < op.paymasterAndData.length ? length : op.paymasterAndData.length;
        for (uint256 i; i < copyLength; ++i) {
            payload[i] = op.paymasterAndData[i];
        }
        op.paymasterAndData = payload;
        mustReject(op);
    }

    receive() external payable {}
}
