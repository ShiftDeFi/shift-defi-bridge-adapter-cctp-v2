// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {BridgeAdapter} from "@shift-defi/core/contracts/BridgeAdapter.sol";
import {Errors} from "@shift-defi/core/contracts/libraries/helpers/Errors.sol";

import {ICCTPv2BridgeAdapter} from "./interfaces/ICCTPv2BridgeAdapter.sol";
import {ITokenMessengerV2} from "./dependencies/interfaces/cctp-v2/ITokenMessengerV2.sol";
import {IMessageTransmitter} from "./dependencies/interfaces/cctp-v2/IMessageTransmitter.sol";

contract CCTPv2BridgeAdapter is ICCTPv2BridgeAdapter, BridgeAdapter {
    using SafeERC20 for IERC20;

    address public tokenMessengerV2;
    address public messageTransmitter;
    address public usdc;

    uint256 private constant MIN_FINALITY_THRESHOLD = 1000;
    uint256 private constant MAX_FINALITY_THRESHOLD = 2000;

    /// @notice Length of the CCTP v2 bridge message with receiver payload
    /// @dev This is the fixed length of the bridge message (356 bytes) plus the 20 byte receiver address payload
    uint256 private constant CCTP_V2_BRIDGE_MESSAGE_WITH_PAYLOAD_LENGTH = 396;

    mapping(uint256 => Domain) private _domainsByChainId;
    mapping(uint32 => uint256) private _chainIdByDomainId;

    /**
     * @notice Initializes the CCTPv2BridgeAdapter contract
     * @dev Sets up the token messenger, message transmitter, and USDC addresses
     * @param _defaultAdmin The default admin address for access control
     * @param _governance The governance address for access control
     * @param _tokenMessengerV2 The address of the TokenMessengerV2 contract
     * @param _usdc The address of the USDC token contract
     */
    function initialize(
        address _defaultAdmin,
        address _governance,
        address _tokenMessengerV2,
        address _usdc
    ) external initializer {
        require(_tokenMessengerV2 != address(0), Errors.ZeroAddress());
        require(_usdc != address(0), Errors.ZeroAddress());
        tokenMessengerV2 = _tokenMessengerV2;
        usdc = _usdc;
        messageTransmitter = ITokenMessengerV2(_tokenMessengerV2).localMessageTransmitter();
        __BridgeAdapter_init(_defaultAdmin, _governance);
    }

    /// @inheritdoc ICCTPv2BridgeAdapter
    function whitelistDomain(uint256 chainId, uint32 domainId) external onlyRole(GOVERNANCE_ROLE) {
        require(chainId > 0, IncorrectChainId(chainId));
        require(domainId > 0, IncorrectDomainId(domainId));

        Domain storage domain = _domainsByChainId[chainId];
        require(!domain.isWhitelisted, Errors.AlreadyWhitelisted());
        domain.domainId = domainId;
        domain.isWhitelisted = true;
        _chainIdByDomainId[domainId] = chainId;
        emit DomainWhitelisted(chainId, domainId);
    }

    /// @inheritdoc ICCTPv2BridgeAdapter
    function blacklistDomain(uint256 chainId, uint32 domainId) external onlyRole(GOVERNANCE_ROLE) {
        require(chainId > 0, IncorrectChainId(chainId));
        require(domainId > 0, IncorrectDomainId(domainId));

        Domain storage domain = _domainsByChainId[chainId];
        require(domain.isWhitelisted, Errors.AlreadyBlacklisted());
        domain.isWhitelisted = false;
        emit DomainBlacklisted(chainId, domainId);
    }

    /// @inheritdoc ICCTPv2BridgeAdapter
    function encodeCCTPV2Payload(
        uint256 maxFee,
        uint32 bridgeMinFinalityThreshold
    ) external pure returns (bytes memory) {
        return abi.encode(maxFee, bridgeMinFinalityThreshold);
    }

    /// @inheritdoc ICCTPv2BridgeAdapter
    function decodeCCTPV2Payload(bytes memory payload) public pure returns (CCTPV2Payload memory) {
        return abi.decode(payload, (CCTPV2Payload));
    }

    /// @inheritdoc ICCTPv2BridgeAdapter
    function getDomainId(uint256 chainId) public view returns (uint32) {
        return _domainsByChainId[chainId].domainId;
    }

    function _bridge(
        BridgeInstruction calldata instruction,
        address receiver,
        address peer
    ) internal override returns (uint256) {
        CCTPV2Payload memory decodedPayload = decodeCCTPV2Payload(instruction.payload);
        _validatePayload(instruction, decodedPayload);

        address usdcCached = usdc;
        address tokenMessengerV2Cached = tokenMessengerV2;

        bytes32 peerBytes32 = bytes32(uint256(uint160(peer)));
        IERC20(usdcCached).safeIncreaseAllowance(tokenMessengerV2Cached, instruction.amount);
        ITokenMessengerV2(tokenMessengerV2Cached).depositForBurnWithHook(
            instruction.amount,
            _domainsByChainId[instruction.chainTo].domainId,
            peerBytes32,
            usdcCached,
            peerBytes32,
            decodedPayload.maxFee,
            decodedPayload.bridgeMinFinalityThreshold,
            abi.encodePacked(receiver)
        );

        return instruction.amount - decodedPayload.maxFee;
    }

    function _validatePayload(
        BridgeInstruction calldata instruction,
        CCTPV2Payload memory decodedPayload
    ) internal view {
        require(instruction.token == usdc, NotUsdc());
        require(_domainsByChainId[instruction.chainTo].isWhitelisted, NotWhitelistedDomain(instruction.chainTo));
        require(
            instruction.minTokenAmount + decodedPayload.maxFee <= instruction.amount,
            NotEnoughAmount(instruction.minTokenAmount + decodedPayload.maxFee, instruction.amount)
        );
        require(
            decodedPayload.bridgeMinFinalityThreshold >= MIN_FINALITY_THRESHOLD &&
                decodedPayload.bridgeMinFinalityThreshold <= MAX_FINALITY_THRESHOLD,
            MinFinalityThresholdNotInRange(decodedPayload.bridgeMinFinalityThreshold)
        );
    }

    /// @inheritdoc ICCTPv2BridgeAdapter
    function claimCCTPBridge(
        bytes calldata bridgeMessage,
        bytes calldata bridgeAttestation
    ) external nonReentrant {
        address usdcCached = usdc;
        uint256 amountBeforeClaim = IERC20(usdcCached).balanceOf(address(this));
        require(
            IMessageTransmitter(messageTransmitter).receiveMessage(bridgeMessage, bridgeAttestation),
            FailedMessageReceive()
        );
        uint256 amountAfterClaim = IERC20(usdcCached).balanceOf(address(this));
        uint256 amountClaimed = amountAfterClaim - amountBeforeClaim;
        require(amountClaimed > 0, Errors.ZeroAmount());

        address receiver = _extractReceiverFromBridgeMessage(bridgeMessage);

        _finalizeBridge(receiver, usdcCached, amountClaimed);
    }

    /**
     * @notice Extracts receiver EVM address from the CCTP bridge message
     * @dev Receiver is encoded in the last 20 bytes of the bridge message payload
     * @param bridgeMessage The full CCTP bridge message bytes
     * @return receiver The extracted receiver address
     */
    function _extractReceiverFromBridgeMessage(
        bytes calldata bridgeMessage
    ) internal pure returns (address receiver) {
        require(bridgeMessage.length == CCTP_V2_BRIDGE_MESSAGE_WITH_PAYLOAD_LENGTH, InvalidBridgeMessageLength(bridgeMessage.length));
        uint256 offset = bridgeMessage.length - 20;
        assembly {
            let data := calldataload(add(bridgeMessage.offset, offset))
            receiver := shr(96, data)
        }
    }
}
