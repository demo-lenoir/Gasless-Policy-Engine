// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.37;

contract DemoCounter {
    uint256 public count;
    bytes32 public lastReference;

    event Incremented(bytes32 indexed refId, uint256 count);

    function increment(bytes32 refId) external {
        count++;
        lastReference = refId;
        emit Incremented(refId, count);
    }

    function fail() external pure {
        revert("demo target failure");
    }
}
