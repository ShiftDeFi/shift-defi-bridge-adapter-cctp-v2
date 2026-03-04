// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {CCTPv2BridgeAdapter} from "../contracts/CCTPv2BridgeAdapter.sol";
import {ICCTPv2BridgeAdapter} from "../contracts/interfaces/ICCTPv2BridgeAdapter.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IBridgeAdapter} from "@shift-defi/core/contracts/interfaces/IBridgeAdapter.sol";
import {Errors} from "@shift-defi/core/contracts/libraries/helpers/Errors.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface ITokenMessengerV2 {
    function localMessageTransmitter() external view returns (address);
}

interface IMessageTransmitter {
    function attesterManager() external view returns (address);
    function enableAttester(address attester) external;
    function signatureThreshold() external view returns (uint256);
}

contract MockERC20 is IERC20 {
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function totalSupply() external pure override returns (uint256) {
        return 0;
    }

    function name() external pure returns (string memory) {
        return "Mock";
    }

    function symbol() external pure returns (string memory) {
        return "MOCK";
    }

    function decimals() external pure returns (uint8) {
        return 6;
    }
}

contract CCTPv2BridgeAdapterTest is Test {
    CCTPv2BridgeAdapter public l1Peer;
    CCTPv2BridgeAdapter public l2Peer;

    uint256 public l1ForkId;
    uint256 public l2ForkId;

    struct Roles {
        address defaultAdmin;
        address governance;
        address bridger;
    }

    Roles public roles = Roles({
        defaultAdmin: makeAddr("defaultAdmin"),
        governance: makeAddr("governance"),
        bridger: makeAddr("bridger")
    });

    address receiver = makeAddr("receiver");

    uint256 public constant MIN_BRIDGE_AMOUNT = 1e6;
    uint256 public constant MAX_BRIDGE_AMOUNT = 100_000e6;
    uint256 public constant MIN_MAX_FEE = 1e5;
    uint256 public constant MAX_MAX_FEE = 10e6;
    uint256 public constant MIN_FINALITY_THRESHOLD = 1000;
    uint256 public constant MAX_FINALITY_THRESHOLD = 2000;
    uint256 public constant SLIPPAGE_CAP_PCT = 1000;
    uint256 public constant CCTP_V2_BRIDGE_MESSAGE_WITH_PAYLOAD_LENGTH = 396;

    uint256[] public l1Attesters;
    uint256[] public l2Attesters;

    struct Fork {
        string rpc;
        address tokenMessengerV2;
        address usdc;
        uint256 chainId;
        uint32 domainId;
    }

    Fork l1Fork;
    Fork l2Fork;

    uint256 public baseL1SnapshotId;
    uint256 public baseL2SnapshotId;

    function _setUp(Fork memory _l1Fork, Fork memory _l2Fork) internal {
        l1Fork = _l1Fork;
        l2Fork = _l2Fork;

        l1ForkId = vm.createFork(l1Fork.rpc);
        l2ForkId = vm.createFork(l2Fork.rpc);

        l1Peer = _deployAndSetupProxy(l1ForkId, roles, l1Fork);
        l2Peer = _deployAndSetupProxy(l2ForkId, roles, l2Fork);

        vm.selectFork(l1ForkId);
        l1Attesters = _setupAttesters(l1ForkId, l1Fork);
        vm.startPrank(roles.governance);
        l1Peer.whitelistBridger(roles.bridger);
        l1Peer.whitelistDomain(l2Fork.chainId, l2Fork.domainId);
        l1Peer.setPeer(l2Fork.chainId, address(l2Peer));
        l1Peer.setBridgePath(l1Fork.usdc, l2Fork.chainId, l2Fork.usdc);
        l1Peer.setSlippageCapPct(SLIPPAGE_CAP_PCT);
        vm.stopPrank();

        vm.selectFork(l2ForkId);
        l2Attesters = _setupAttesters(l2ForkId, l2Fork);
        vm.startPrank(roles.governance);
        l2Peer.whitelistBridger(roles.bridger);
        l2Peer.whitelistDomain(l1Fork.chainId, l1Fork.domainId);
        l2Peer.setBridgePath(l2Fork.usdc, l1Fork.chainId, l2Fork.usdc);
        l2Peer.setPeer(l1Fork.chainId, address(l1Peer));
        l2Peer.setSlippageCapPct(SLIPPAGE_CAP_PCT);
        vm.stopPrank();

        baseL1SnapshotId = vm.snapshot();
        baseL2SnapshotId = vm.snapshot();
    }

    function _randomBridgeAmount() internal view returns (uint256) {
        return vm.randomUint(MIN_BRIDGE_AMOUNT, MAX_BRIDGE_AMOUNT);
    }

    function _randomMaxFee() internal view returns (uint256) {
        return vm.randomUint(MIN_MAX_FEE, MAX_MAX_FEE);
    }

    function _randomFinalityThreshold() internal view returns (uint32) {
        return uint32(vm.randomUint(MIN_FINALITY_THRESHOLD, MAX_FINALITY_THRESHOLD));
    }

    function _findBridgeMessageInLogs(Vm.Log[] memory entries) internal view returns (bytes memory) {
        for (uint256 i = 0; i < entries.length; i++) {
            bytes memory logData = entries[i].data;
            if (logData.length < 64) continue;
            try this.decodeLogData(logData) returns (bytes memory decoded) {
                if (decoded.length >= 356 && decoded.length <= 400) {
                    return decoded;
                }
            } catch {}
        }
        revert("Bridge message not found in logs");
    }

    function decodeLogData(bytes memory data) external pure returns (bytes memory) {
        return abi.decode(data, (bytes));
    }

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
            "Bridger balance should decrease by bridged amount"
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
        l2Peer.claimCCTPBridge(bridgeMessage, bridgeAttestationPacked);

        uint256 expectedClaimableAmount = amount - fee;

        assertEq(
            IERC20(l2Fork.usdc).balanceOf(address(l2Peer)),
            expectedClaimableAmount,
            "Adapter should hold claimed USDC amount"
        );
        assertEq(
            l2Peer.claimableAmounts(receiver, l2Fork.usdc),
            expectedClaimableAmount,
            "Receiver should receive claimed USDC amount"
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
            "Domain ID should match whitelisted value"
        );
    }

    function test_WhitelistDomain_RevertIf_AlreadyWhitelisted() public {
        vm.selectFork(l1ForkId);
        vm.prank(roles.governance);
        vm.expectRevert(Errors.AlreadyWhitelisted.selector);
        l1Peer.whitelistDomain(l2Fork.chainId, l2Fork.domainId);
    }

    function test_WhitelistDomain_RevertIf_NotGovernance() public {
        vm.selectFork(l1ForkId);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert();
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
        vm.selectFork(l1ForkId);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert();
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
            "Bridger balance should be zero after bridge"
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
            "Bridger balance should be zero after bridge"
        );
    }

    function test_EncodeDecodeCCTPV2Payload_Roundtrip() public {
        vm.selectFork(l1ForkId);
        uint256 maxFee = _randomMaxFee();
        uint32 bridgeMin = _randomFinalityThreshold();

        bytes memory encoded = l1Peer.encodeCCTPV2Payload(maxFee, bridgeMin);
        ICCTPv2BridgeAdapter.CCTPV2Payload memory decoded = l1Peer.decodeCCTPV2Payload(encoded);

        assertEq(decoded.maxFee, maxFee, "maxFee should match");
        assertEq(decoded.bridgeMinFinalityThreshold, bridgeMin, "bridgeMinFinalityThreshold should match");
    }

    function test_DecodeCCTPV2Payload_RevertIf_InvalidPayload() public {
        vm.selectFork(l1ForkId);
        vm.expectRevert();
        l1Peer.decodeCCTPV2Payload(hex"01");
    }

    function test_ClaimCCTPBridge_RevertIf_InvalidAttestation() public {
        vm.selectFork(l2ForkId);
        bytes memory fakeMessage = new bytes(CCTP_V2_BRIDGE_MESSAGE_WITH_PAYLOAD_LENGTH);
        bytes memory wrongAttestation = abi.encodePacked(bytes32(0));

        vm.expectRevert();
        l2Peer.claimCCTPBridge(fakeMessage, wrongAttestation);
    }

    function test_ClaimCCTPBridge_RevertIf_InvalidBridgeMessageLength() public {
        vm.selectFork(l2ForkId);
        bytes memory shortMessage = new bytes(100);
        bytes memory attestation = _packAttestations(l2Attesters, keccak256(shortMessage));

        vm.expectRevert();
        l2Peer.claimCCTPBridge(shortMessage, attestation);
    }

    function _setupAttesters(uint256 forkId, Fork memory fork) internal returns (uint256[] memory) {
        vm.selectFork(forkId);
        address messageTransmitter = ITokenMessengerV2(fork.tokenMessengerV2).localMessageTransmitter();
        address attesterManager = IMessageTransmitter(messageTransmitter).attesterManager();
        uint256 signatureThreshold = IMessageTransmitter(messageTransmitter).signatureThreshold();

        uint256[] memory attestersPks = new uint256[](signatureThreshold);
        vm.startPrank(attesterManager);
        for (uint256 i = 0; i < signatureThreshold; i++) {
            uint256 pk = vm.randomUint(1, type(uint256).max);
            attestersPks[i] = pk;
            IMessageTransmitter(messageTransmitter).enableAttester(vm.addr(pk));
        }
        vm.stopPrank();
        return attestersPks;
    }

    function _deployAndSetupProxy(
        uint256 forkId,
        Roles memory _roles,
        Fork memory _fork
    ) internal returns (CCTPv2BridgeAdapter) {
        vm.selectFork(forkId);
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(new CCTPv2BridgeAdapter()),
            _roles.defaultAdmin,
            abi.encodeWithSelector(
                CCTPv2BridgeAdapter.initialize.selector,
                _roles.defaultAdmin,
                _roles.governance,
                _fork.tokenMessengerV2,
                _fork.usdc
            )
        );

        CCTPv2BridgeAdapter adapter = CCTPv2BridgeAdapter(address(proxy));
        vm.prank(_roles.defaultAdmin);
        adapter.grantRole(keccak256("GOVERNANCE_ROLE"), _roles.governance);
        return adapter;
    }

    function _sortAttestersByAddress(uint256[] memory pks) internal pure returns (uint256[] memory sorted) {
        sorted = new uint256[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            sorted[i] = pks[i];
        }
        for (uint256 i = 0; i < sorted.length; i++) {
            for (uint256 j = i + 1; j < sorted.length; j++) {
                if (vm.addr(sorted[i]) > vm.addr(sorted[j])) {
                    (sorted[i], sorted[j]) = (sorted[j], sorted[i]);
                }
            }
        }
    }

    function _randomizeNonce(bytes memory message) internal view returns (bytes memory) {
        require(message.length >= 20, "message too short");
        uint64 randomNonce = uint64(
            uint256(keccak256(abi.encode(block.timestamp, block.number, message, msg.sender)))
        );
        for (uint256 i = 0; i < 8; i++) {
            message[12 + i] = bytes1(uint8(randomNonce >> (56 - i * 8)));
        }
        return message;
    }

    function _packAttestations(uint256[] memory pks, bytes32 messageHash) internal pure returns (bytes memory) {
        uint256[] memory sorted = _sortAttestersByAddress(pks);
        bytes memory packed;
        for (uint256 i = 0; i < sorted.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(sorted[i], messageHash);
            packed = bytes.concat(packed, abi.encodePacked(r, s, v));
        }
        return packed;
    }

    function _insertFinalityThreshold(
        bytes memory message,
        uint32 finalityThreshold
    ) internal pure returns (bytes memory) {
        require(message.length >= 148, "message too short");
        require(finalityThreshold >= 500 && finalityThreshold <= 2000, "threshold out of range");
        message[144] = bytes1(uint8(finalityThreshold >> 24));
        message[145] = bytes1(uint8(finalityThreshold >> 16));
        message[146] = bytes1(uint8(finalityThreshold >> 8));
        message[147] = bytes1(uint8(finalityThreshold));
        return message;
    }

    function _insertFee(bytes memory message, uint256 fee) internal pure returns (bytes memory) {
        require(message.length >= 344, "message too short");
        if (fee == 0) return message;
        for (uint256 i = 0; i < 32; i++) {
            message[312 + i] = bytes1(uint8(fee >> (248 - i * 8)));
        }
        return message;
    }
}
