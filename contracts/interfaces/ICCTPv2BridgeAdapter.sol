// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title ICCTPv2BridgeAdapter
 * @author Shift DeFi
 * @notice Interface for the CCTPv2 Bridge Adapter contract
 * @dev This interface defines the functions and structures for bridging assets using Circle's Cross-Chain Transfer Protocol (CCTP) v2
 */
interface ICCTPv2BridgeAdapter {
    struct Domain {
        uint32 domainId;
        bool isWhitelisted;
    }

    struct CCTPV2Payload {
        uint256 maxFee;
        uint32 bridgeMinFinalityThreshold;
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
    error InvalidBridgeMessageLength(uint256 length);

    /**
     * @notice Returns the address of the TokenMessengerV2 contract
     * @return The TokenMessengerV2 contract address
     */
    function tokenMessengerV2() external view returns (address);

    /**
     * @notice Returns the address of the MessageTransmitter contract
     * @return The MessageTransmitter contract address
     */
    function messageTransmitter() external view returns (address);

    /**
     * @notice Returns the address of the USDC token contract
     * @return The USDC token contract address
     */
    function usdc() external view returns (address);

    /**
     * @notice Whitelists a domain for bridging operations
     * @dev Only callable by addresses with GOVERNANCE_ROLE
     * @param chainId The chain ID to whitelist
     * @param domainId The CCTP domain identifier associated with the chain
     */
    function whitelistDomain(uint256 chainId, uint32 domainId) external;

    /**
     * @notice Blacklists a domain from bridging operations
     * @dev Only callable by addresses with GOVERNANCE_ROLE
     * @param chainId The chain ID to blacklist
     * @param domainId The CCTP domain identifier associated with the chain
     */
    function blacklistDomain(uint256 chainId, uint32 domainId) external;

    /**
     * @notice Encodes CCTPv2 payload parameters into bytes
     * @dev Helper function to encode bridge configuration parameters
     * @param maxFee Maximum fee allowed for the bridge transaction
     * @param bridgeMinFinalityThreshold Minimum finality threshold for the bridge message (must be between 1000-2000)
     * @return The encoded payload bytes
     */
    function encodeCCTPV2Payload(
        uint256 maxFee,
        uint32 bridgeMinFinalityThreshold
    ) external pure returns (bytes memory);

    /**
     * @notice Decodes CCTPv2 payload bytes into structured data
     * @dev Helper function to decode bridge configuration parameters
     * @param payload The encoded payload bytes
     * @return The decoded CCTPV2Payload structure
     */
    function decodeCCTPV2Payload(bytes memory payload) external pure returns (CCTPV2Payload memory);

    /**
     * @notice Claims bridged USDC tokens using a single CCTP bridge message
     * @dev Verifies the bridge message via MessageTransmitter and credits the receiver embedded in the message payload
     * @param bridgeMessage The encoded bridge message containing token transfer and receiver information
     * @param bridgeAttestation The attestation for the bridge message
     */
    function claimCCTPBridge(
        bytes calldata bridgeMessage,
        bytes calldata bridgeAttestation
    ) external;

    /**
     * @notice Returns the CCTP domain id for a given EVM chain id
     * @param chainId The EVM chain id
     * @return domainId The corresponding CCTP domain id
     */
    function getDomainId(uint256 chainId) external view returns (uint32 domainId);
}
