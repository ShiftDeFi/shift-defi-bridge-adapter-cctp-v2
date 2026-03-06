// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Base, IMessageTransmitter} from "./Base.t.sol";
import {Vm} from "forge-std/Vm.sol";
import {ICCTPv2BridgeAdapter} from "../contracts/interfaces/ICCTPv2BridgeAdapter.sol";
import {IBridgeAdapter} from "@shift-defi/core/contracts/interfaces/IBridgeAdapter.sol";
import {Errors} from "@shift-defi/core/contracts/libraries/helpers/Errors.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IAccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

abstract contract CCTPv2BridgeAdapterTest is Base {
    function test_Bridge() public {
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();
        uint256 minTokenAmount = amount - maxFee - 1;
        uint32 finality = _randomFinalityThreshold();

        vm.selectFork(l1ForkId);
        deal(l1Fork.usdc, roles.bridger, amount);

        uint256 balanceBefore = IERC20(l1Fork.usdc).balanceOf(roles.bridger);

        vm.startPrank(roles.bridger);
        IERC20(l1Fork.usdc).approve(address(l1Peer), amount);
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: l1Fork.usdc,
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: minTokenAmount,
                payload: l1Peer.encodeCCTPV2Payload(maxFee, finality)
            }),
            receiver
        );
        vm.stopPrank();

        assertEq(
            IERC20(l1Fork.usdc).balanceOf(roles.bridger),
            balanceBefore - amount,
            "test_Bridge: Bridger balance should decrease by bridged amount"
        );
    }

    function test_Claim() public {
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();
        uint256 minTokenAmount = amount - maxFee - 1;
        uint32 unfinalizedThreshold = uint32(
            vm.randomUint(MIN_FINALITY_THRESHOLD, MAX_FINALITY_THRESHOLD)
        );

        vm.selectFork(l1ForkId);
        deal(l1Fork.usdc, roles.bridger, amount);

        vm.recordLogs();
        vm.startPrank(roles.bridger);
        IERC20(l1Fork.usdc).approve(address(l1Peer), amount);
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: l1Fork.usdc,
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: minTokenAmount,
                payload: l1Peer.encodeCCTPV2Payload(maxFee, unfinalizedThreshold)
            }),
            receiver
        );
        vm.stopPrank();

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bytes memory bridgeMessage = _findBridgeMessageInLogs(entries);

        bridgeMessage = _randomizeNonce(bridgeMessage);
        bridgeMessage = _insertFinalityThreshold(bridgeMessage, unfinalizedThreshold);
        uint256 fee = vm.randomUint(0, maxFee);
        bridgeMessage = _insertFee(bridgeMessage, fee);

        bytes memory bridgeAttestationPacked = _packAttestations(l2Attesters, keccak256(bridgeMessage));

        vm.selectFork(l2ForkId);
        vm.prank(roles.claimer);
        l2Peer.claimCCTPBridge(bridgeMessage, bridgeAttestationPacked);

        uint256 expectedClaimableAmount = amount - fee;

        assertEq(
            IERC20(l2Fork.usdc).balanceOf(address(l2Peer)),
            expectedClaimableAmount,
            "test_Claim: Adapter should hold claimed USDC amount"
        );
        assertEq(
            l2Peer.claimableAmounts(receiver, l2Fork.usdc),
            expectedClaimableAmount,
            "test_Claim: Receiver should receive claimed USDC amount"
        );
    }

    function test_WhitelistDomain_Success() public {
        vm.selectFork(l1ForkId);
        uint256 newChainId = 99_999;
        uint32 newDomainId = 99;

        vm.prank(roles.governance);
        l1Peer.whitelistDomain(newChainId, newDomainId);

        assertEq(
            l1Peer.getDomainId(newChainId),
            newDomainId,
            "test_WhitelistDomain_Success: Domain ID should match whitelisted value"
        );
    }

    function test_WhitelistDomain_RevertIf_AlreadyWhitelisted() public {
        vm.selectFork(l1ForkId);
        vm.prank(roles.governance);
        vm.expectRevert(Errors.AlreadyWhitelisted.selector);
        l1Peer.whitelistDomain(l2Fork.chainId, l2Fork.domainId);
    }

    function test_WhitelistDomain_RevertIf_NotGovernance() public {
        address stranger = makeAddr("stranger");
        vm.selectFork(l1ForkId);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, GOVERNANCE_ROLE));
        l1Peer.whitelistDomain(99_999, 99);
    }

    function test_WhitelistDomain_RevertIf_ChainIdZero() public {
        vm.selectFork(l1ForkId);
        vm.prank(roles.governance);
        vm.expectRevert(abi.encodeWithSelector(ICCTPv2BridgeAdapter.IncorrectChainId.selector, 0));
        l1Peer.whitelistDomain(0, l2Fork.domainId);
    }

    function test_BlacklistDomain_Success() public {
        vm.selectFork(l1ForkId);
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();
        uint256 minTokenAmount = amount - maxFee - 1;
        uint32 finality = _randomFinalityThreshold();

        vm.prank(roles.governance);
        l1Peer.blacklistDomain(l2Fork.chainId, l2Fork.domainId);
        deal(l1Fork.usdc, roles.bridger, amount);

        bytes memory payload = l1Peer.encodeCCTPV2Payload(maxFee, finality);

        vm.startPrank(roles.bridger);
        IERC20(l1Fork.usdc).approve(address(l1Peer), amount);
        vm.expectRevert(
            abi.encodeWithSelector(ICCTPv2BridgeAdapter.NotWhitelistedDomain.selector, l2Fork.chainId)
        );
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: l1Fork.usdc,
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: minTokenAmount,
                payload: payload
            }),
            receiver
        );
        vm.stopPrank();
    }

    function test_BlacklistDomain_RevertIf_AlreadyBlacklisted() public {
        vm.selectFork(l1ForkId);
        vm.startPrank(roles.governance);
        l1Peer.blacklistDomain(l2Fork.chainId, l2Fork.domainId);
        vm.expectRevert(Errors.AlreadyBlacklisted.selector);
        l1Peer.blacklistDomain(l2Fork.chainId, l2Fork.domainId);
        vm.stopPrank();
    }

    function test_BlacklistDomain_RevertIf_NotGovernance() public {
        address stranger = makeAddr("stranger");
        vm.selectFork(l1ForkId);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, GOVERNANCE_ROLE));
        l1Peer.blacklistDomain(l2Fork.chainId, l2Fork.domainId);
    }

    function test_BlacklistDomain_RevertIf_ChainIdZero() public {
        vm.selectFork(l1ForkId);
        vm.prank(roles.governance);
        vm.expectRevert(abi.encodeWithSelector(ICCTPv2BridgeAdapter.IncorrectChainId.selector, 0));
        l1Peer.blacklistDomain(0, l2Fork.domainId);
    }

    function test_Bridge_RevertIf_NotUsdc() public {
        vm.selectFork(l1ForkId);
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();

        MockERC20 otherToken = new MockERC20();
        otherToken.mint(roles.bridger, amount);

        vm.startPrank(roles.governance);
        l1Peer.setBridgePath(address(otherToken), l2Fork.chainId, l2Fork.usdc);
        vm.stopPrank();

        bytes memory payload = l1Peer.encodeCCTPV2Payload(maxFee, 1500);

        vm.startPrank(roles.bridger);
        otherToken.approve(address(l1Peer), amount);
        vm.expectRevert(ICCTPv2BridgeAdapter.NotUsdc.selector);
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: address(otherToken),
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: amount - maxFee - 1,
                payload: payload
            }),
            receiver
        );
        vm.stopPrank();
    }

    function test_Bridge_RevertIf_NotWhitelistedDomain() public {
        vm.selectFork(l1ForkId);
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();

        vm.prank(roles.governance);
        l1Peer.blacklistDomain(l2Fork.chainId, l2Fork.domainId);
        deal(l1Fork.usdc, roles.bridger, amount);

        bytes memory payload = l1Peer.encodeCCTPV2Payload(maxFee, 1500);

        vm.startPrank(roles.bridger);
        IERC20(l1Fork.usdc).approve(address(l1Peer), amount);
        vm.expectRevert(
            abi.encodeWithSelector(ICCTPv2BridgeAdapter.NotWhitelistedDomain.selector, l2Fork.chainId)
        );
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: l1Fork.usdc,
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: amount - maxFee - 1,
                payload: payload
            }),
            receiver
        );
        vm.stopPrank();
    }

    function test_Bridge_RevertIf_MinFinalityThresholdOutOfRange() public {
        vm.selectFork(l1ForkId);
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();

        deal(l1Fork.usdc, roles.bridger, amount);
        bytes memory payload = l1Peer.encodeCCTPV2Payload(maxFee, 999);

        vm.startPrank(roles.bridger);
        IERC20(l1Fork.usdc).approve(address(l1Peer), amount);
        vm.expectRevert(
            abi.encodeWithSelector(ICCTPv2BridgeAdapter.MinFinalityThresholdNotInRange.selector, uint32(999))
        );
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: l1Fork.usdc,
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: amount - maxFee - 1,
                payload: payload
            }),
            receiver
        );
        vm.stopPrank();
    }

    function test_Bridge_RevertIf_FinalityThresholdAboveMax() public {
        vm.selectFork(l1ForkId);
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();

        deal(l1Fork.usdc, roles.bridger, amount);
        bytes memory payload = l1Peer.encodeCCTPV2Payload(maxFee, 2001);

        vm.startPrank(roles.bridger);
        IERC20(l1Fork.usdc).approve(address(l1Peer), amount);
        vm.expectRevert(
            abi.encodeWithSelector(ICCTPv2BridgeAdapter.MinFinalityThresholdNotInRange.selector, uint32(2001))
        );
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: l1Fork.usdc,
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: amount - maxFee - 1,
                payload: payload
            }),
            receiver
        );
        vm.stopPrank();
    }

    function test_Bridge_FinalityThresholdBoundary_Min() public {
        vm.selectFork(l1ForkId);
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();

        deal(l1Fork.usdc, roles.bridger, amount);
        bytes memory payload = l1Peer.encodeCCTPV2Payload(maxFee, uint32(MIN_FINALITY_THRESHOLD));

        vm.startPrank(roles.bridger);
        IERC20(l1Fork.usdc).approve(address(l1Peer), amount);
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: l1Fork.usdc,
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: amount - maxFee - 1,
                payload: payload
            }),
            receiver
        );
        vm.stopPrank();

        assertEq(
            IERC20(l1Fork.usdc).balanceOf(roles.bridger),
            0,
            "test_Bridge_FinalityThresholdBoundary_Min: Bridger balance should be zero after bridge"
        );
    }

    function test_Bridge_FinalityThresholdBoundary_Max() public {
        vm.selectFork(l1ForkId);
        uint256 amount = _randomBridgeAmount();
        uint256 maxFee = _randomMaxFee();

        deal(l1Fork.usdc, roles.bridger, amount);
        bytes memory payload = l1Peer.encodeCCTPV2Payload(maxFee, uint32(MAX_FINALITY_THRESHOLD));

        vm.startPrank(roles.bridger);
        IERC20(l1Fork.usdc).approve(address(l1Peer), amount);
        l1Peer.bridge(
            IBridgeAdapter.BridgeInstruction({
                token: l1Fork.usdc,
                amount: amount,
                chainTo: l2Fork.chainId,
                minTokenAmount: amount - maxFee - 1,
                payload: payload
            }),
            receiver
        );
        vm.stopPrank();

        assertEq(
            IERC20(l1Fork.usdc).balanceOf(roles.bridger),
            0,
            "test_Bridge_FinalityThresholdBoundary_Max: Bridger balance should be zero after bridge"
        );
    }

    function test_EncodeDecodeCCTPV2Payload_Roundtrip() public {
        vm.selectFork(l1ForkId);
        uint256 maxFee = _randomMaxFee();
        uint32 bridgeMin = _randomFinalityThreshold();

        bytes memory encoded = l1Peer.encodeCCTPV2Payload(maxFee, bridgeMin);
        ICCTPv2BridgeAdapter.CCTPV2Payload memory decoded = l1Peer.decodeCCTPV2Payload(encoded);

        assertEq(decoded.maxFee, maxFee, "test_EncodeDecodeCCTPV2Payload_Roundtrip: maxFee should match");
        assertEq(decoded.bridgeMinFinalityThreshold, bridgeMin, "test_EncodeDecodeCCTPV2Payload_Roundtrip: bridgeMinFinalityThreshold should match");
    }

    function test_DecodeCCTPV2Payload_RevertIf_InvalidPayload() public {
        vm.selectFork(l1ForkId);
        vm.expectRevert();
        l1Peer.decodeCCTPV2Payload(hex"01");
    }

    function test_ClaimCCTPBridge_RevertIf_InvalidMessageReceive() public {
        vm.selectFork(l2ForkId);
        bytes memory message = new bytes(CCTP_V2_BRIDGE_MESSAGE_WITH_PAYLOAD_LENGTH);
        bytes memory attestation = _packAttestations(l2Attesters, keccak256(message));

        vm.mockCall(
            l2Peer.messageTransmitter(),
            abi.encodeWithSelector(IMessageTransmitter.receiveMessage.selector, message, attestation),
            abi.encode(false)
        );

        vm.expectRevert(abi.encodeWithSelector(ICCTPv2BridgeAdapter.FailedMessageReceive.selector));
        vm.prank(roles.claimer);
        l2Peer.claimCCTPBridge(message, attestation);
    }
}
