// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IMessageTransmitter {
    function enableAttester(address attester) external;
    function receiveMessage(bytes memory message, bytes memory attestation) external returns (bool);
    function sendMessage(
        uint32 destinationDomain,
        bytes32 recipient,
        bytes32 destinationRecipient,
        uint32 minFinalityThreshold,
        bytes memory messageBody
    ) external;
}
