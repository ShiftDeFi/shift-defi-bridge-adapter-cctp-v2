// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface ICCTPv2BridgeAdapter {
    struct Domain {
        uint32 domainId;
        bool isWhitelisted;
    }

    struct CCTPV2Payload {
        uint256 maxFee;
        uint32 bridgeMinFinalityThreshold;
        uint32 messageMinFinalityThreshold;
    }

    event DomainWhitelisted(uint256 indexed chainId, uint32 indexed domainId);
    event DomainBlacklisted(uint256 indexed chainId, uint32 indexed domainId);

    error NotUsdc();
    error NotWhitelistedDomain(uint256 chainId);
    error NotEnoughAmount(uint256 minTokenAmount, uint256 amount);
    error MinFinalityThresholdNotInRange(uint32 minFinalityThreshold);
    error MaxFinalityThresholdNotInRange(uint32 maxFinalityThreshold);
    error NotMessageTransmitter(address sender, address messageTransmitter);
    error DomainsNotMatch(uint256 chainId, uint32 domainId);
    error IncorrectChainId(uint256 chainId);
    error IncorrectDomainId(uint32 domainId);
    error DomainNotWhitelisted(uint256 chainId, uint32 domainId);
    error NotUsdcInBridgeInstruction(address token);
    error FailedMessageReceive();

    function tokenMessengerV2() external view returns (address);
    function messageTransmitter() external view returns (address);
    function usdc() external view returns (address);

    function handleReceiveFinalizedMessage(
        uint32 sourceDomain,
        bytes32 sender,
        uint32 minFinalityThreshold,
        bytes calldata messageBody
    ) external returns (bool);

    function whitelistDomain(uint256 chainId, uint32 domainId) external;
    function blacklistDomain(uint256 chainId, uint32 domainId) external;
    function encodeCCTPV2Payload(
        uint256 maxFee,
        uint32 bridgeMinFinalityThreshold,
        uint32 messageMinFinalityThreshold
    ) external pure returns (bytes memory);
    function decodeCCTPV2Payload(bytes memory payload) external pure returns (CCTPV2Payload memory);
    function claimCCTPBridge(
        bytes calldata bridgeMessage,
        bytes calldata bridgeAttestation,
        bytes calldata messageMessage,
        bytes calldata messageAttestion
    ) external;
}
