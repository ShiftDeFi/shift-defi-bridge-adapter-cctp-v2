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
     * @notice Handles a finalized message received from the message transmitter
     * @dev This function is called by the message transmitter when a message is finalized on the destination chain
     * @param sourceDomain The source domain ID where the message originated
     * @param sender The sender address encoded as bytes32
     * @param minFinalityThreshold The minimum finality threshold that was executed (unused parameter)
     * @param messageBody The message body containing the receiver address
     * @return True if the message was successfully processed
     */
    function handleReceiveFinalizedMessage(
        uint32 sourceDomain,
        bytes32 sender,
        uint32 minFinalityThreshold,
        bytes calldata messageBody
    ) external returns (bool);

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
     * @param messageMinFinalityThreshold Minimum finality threshold for the receiver message (must be between 1000-2000)
     * @return The encoded payload bytes
     */
    function encodeCCTPV2Payload(
        uint256 maxFee,
        uint32 bridgeMinFinalityThreshold,
        uint32 messageMinFinalityThreshold
    ) external pure returns (bytes memory);

    /**
     * @notice Decodes CCTPv2 payload bytes into structured data
     * @dev Helper function to decode bridge configuration parameters
     * @param payload The encoded payload bytes
     * @return The decoded CCTPV2Payload structure
     */
    function decodeCCTPV2Payload(bytes memory payload) external pure returns (CCTPV2Payload memory);

    /**
     * @notice Claims bridged USDC tokens and processes the associated message
     * @dev This function receives two messages: one for the bridge (USDC tokens) and one for the receiver information.
     *      Uses transient storage to pass the claimed amount between message receptions.
     * @param bridgeMessage The encoded bridge message containing token transfer information
     * @param bridgeAttestation The attestation for the bridge message
     * @param messageMessage The encoded message containing receiver information
     * @param messageAttestion The attestation for the receiver message
     */
    function claimCCTPBridge(
        bytes calldata bridgeMessage,
        bytes calldata bridgeAttestation,
        bytes calldata messageMessage,
        bytes calldata messageAttestion
    ) external;
}
