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

    // Transient storage slot for amount claimed during bridge claim
    // uint256(keccak256("CCTP_AMOUNT_CLAIMED"))
    uint256 private constant TRANSIENT_STORAGE_SLOT_AMOUNT_CLAIMED =
        91252728200670152002459531059255922075468269428108162438568888169768460224758;

    mapping(uint256 => Domain) private _domainsByChainId;
    mapping(uint32 => uint256) private _chainIdByDomainId;

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

    function blacklistDomain(uint256 chainId, uint32 domainId) external onlyRole(GOVERNANCE_ROLE) {
        require(chainId > 0, IncorrectChainId(chainId));
        require(domainId > 0, IncorrectDomainId(domainId));

        Domain storage domain = _domainsByChainId[chainId];
        require(domain.isWhitelisted, Errors.AlreadyBlacklisted());
        domain.isWhitelisted = false;
        emit DomainBlacklisted(chainId, domainId);
    }

    function encodeCCTPV2Payload(
        uint256 maxFee,
        uint32 bridgeMinFinalityThreshold,
        uint32 messageMinFinalityThreshold
    ) external pure returns (bytes memory) {
        return abi.encode(maxFee, bridgeMinFinalityThreshold, messageMinFinalityThreshold);
    }

    function decodeCCTPV2Payload(bytes memory payload) public pure returns (CCTPV2Payload memory) {
        return abi.decode(payload, (CCTPV2Payload));
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
        ITokenMessengerV2(tokenMessengerV2Cached).depositForBurn(
            instruction.amount,
            _domainsByChainId[instruction.chainTo].domainId,
            peerBytes32,
            usdcCached,
            peerBytes32,
            decodedPayload.maxFee,
            decodedPayload.bridgeMinFinalityThreshold
        );

        IMessageTransmitter(messageTransmitter).sendMessage(
            _domainsByChainId[instruction.chainTo].domainId,
            peerBytes32,
            peerBytes32,
            decodedPayload.messageMinFinalityThreshold,
            abi.encode(receiver)
        );
        return instruction.amount;
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
        require(
            decodedPayload.messageMinFinalityThreshold >= MIN_FINALITY_THRESHOLD &&
                decodedPayload.messageMinFinalityThreshold <= MAX_FINALITY_THRESHOLD,
            MaxFinalityThresholdNotInRange(decodedPayload.messageMinFinalityThreshold)
        );
    }

    //  Structure of CCTPv2 message:
    //  * version                      4          uint32     0
    //  * sourceDomain                 4          uint32     4
    //  * destinationDomain            4          uint32     8
    //  * nonce                        32         bytes32    12
    //  * sender                       32         bytes32    44
    //  * recipient                    32         bytes32    76
    //  * destinationCaller            32         bytes32    108
    //  * minFinalityThreshold         4          uint32     140
    //  * finalityThresholdExecuted    4          uint32     144
    //  * messageBody                  dynamic    bytes      148

    function claimCCTPBridge(
        bytes calldata bridgeMessage,
        bytes calldata bridgeAttestation,
        bytes calldata messageMessage,
        bytes calldata messageAttestion
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
        uint256 slot = TRANSIENT_STORAGE_SLOT_AMOUNT_CLAIMED;
        assembly {
            tstore(slot, amountClaimed)
        }
        require(
            IMessageTransmitter(messageTransmitter).receiveMessage(messageMessage, messageAttestion),
            FailedMessageReceive()
        );

        assembly {
            // free transient storage slot
            tstore(slot, 0)
        }
    }

    function handleReceiveFinalizedMessage(
        uint32 sourceDomain,
        bytes32 sender,
        uint32,
        bytes calldata messageBody
    ) external override returns (bool) {
        require(msg.sender == messageTransmitter, NotMessageTransmitter(msg.sender, messageTransmitter));
        uint256 chainFromId = _chainIdByDomainId[sourceDomain];

        require(_domainsByChainId[chainFromId].isWhitelisted, NotWhitelistedDomain(sourceDomain));
        require(_domainsByChainId[chainFromId].domainId == sourceDomain, DomainsNotMatch(chainFromId, sourceDomain));

        address senderAddress = address(uint160(uint256(sender)));
        address receiver = abi.decode(messageBody, (address));
        address expectedPeer = peers[chainFromId];

        require(senderAddress == expectedPeer, NotPeer(senderAddress, expectedPeer));

        uint256 slot = TRANSIENT_STORAGE_SLOT_AMOUNT_CLAIMED;
        uint256 amountClaimed;
        assembly {
            amountClaimed := tload(slot)
        }
        _finalizeBridge(receiver, usdc, amountClaimed);
        return true;
    }
}
