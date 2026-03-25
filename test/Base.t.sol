// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {CCTPv2BridgeAdapter} from "../contracts/CCTPv2BridgeAdapter.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

interface ITokenMessengerV2 {
    function localMessageTransmitter() external view returns (address);
}

interface IMessageTransmitter {
    function attesterManager() external view returns (address);
    function enableAttester(address attester) external;
    function signatureThreshold() external view returns (uint256);
    function receiveMessage(bytes memory message, bytes memory attestation) external returns (bool);
}

abstract contract Base is Test {
    CCTPv2BridgeAdapter public l1Peer;
    CCTPv2BridgeAdapter public l2Peer;

    uint256 public l1ForkId;
    uint256 public l2ForkId;

    struct Roles {
        address defaultAdmin;
        address bridgeAdapterManager;
        address cacheManager;
        address bridger;
        address claimer;
    }

    Roles public roles =
        Roles({
            defaultAdmin: makeAddr("defaultAdmin"),
            bridgeAdapterManager: makeAddr("bridgeAdapterManager"),
            cacheManager: makeAddr("cacheManager"),
            bridger: makeAddr("bridger"),
            claimer: makeAddr("claimer")
        });

    address receiver = makeAddr("receiver");

    bytes32 public constant BRIDGE_ADAPTER_MANAGER_ROLE = keccak256("BRIDGE_ADAPTER_MANAGER_ROLE");
    bytes32 public constant CACHE_MANAGER_ROLE = keccak256("CACHE_MANAGER_ROLE");
    bytes32 public constant CLAIMER_ROLE = keccak256("CLAIMER_ROLE");

    uint256 public constant MIN_BRIDGE_AMOUNT = 1e6;
    uint256 public constant MAX_BRIDGE_AMOUNT = 100_000e6;
    uint256 public constant MIN_MAX_FEE = 1e5;
    uint256 public constant MAX_MAX_FEE = 10e6;
    uint256 public constant MIN_FINALITY_THRESHOLD = 1000;
    uint256 public constant MAX_FINALITY_THRESHOLD = 2000;
    uint256 public constant BRIDGE_CACHE_MAX_SIZE = 8;
    uint256 public constant SLIPPAGE_CAP_PCT = 1e17;
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

        l1Peer = _proxify(l1ForkId, roles, l1Fork);
        l2Peer = _proxify(l2ForkId, roles, l2Fork);

        vm.selectFork(l1ForkId);
        l1Attesters = _setupAttesters(l1ForkId, l1Fork);
        vm.startPrank(roles.bridgeAdapterManager);
        l1Peer.whitelistBridger(roles.bridger);
        l1Peer.whitelistDomain(l2Fork.chainId, l2Fork.domainId);
        l1Peer.setPeer(l2Fork.chainId, address(l2Peer));
        l1Peer.setBridgePath(l1Fork.usdc, l2Fork.chainId, l2Fork.usdc);
        vm.stopPrank();

        vm.selectFork(l2ForkId);
        l2Attesters = _setupAttesters(l2ForkId, l2Fork);
        vm.startPrank(roles.bridgeAdapterManager);
        l2Peer.whitelistBridger(roles.bridger);
        l2Peer.whitelistDomain(l1Fork.chainId, l1Fork.domainId);
        l2Peer.setBridgePath(l2Fork.usdc, l1Fork.chainId, l2Fork.usdc);
        l2Peer.setPeer(l1Fork.chainId, address(l1Peer));
        vm.stopPrank();
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

    function _proxify(uint256 forkId, Roles memory _roles, Fork memory _fork) internal returns (CCTPv2BridgeAdapter) {
        vm.selectFork(forkId);
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(new CCTPv2BridgeAdapter()),
            _roles.defaultAdmin,
            abi.encodeWithSelector(
                CCTPv2BridgeAdapter.initialize.selector,
                _roles.defaultAdmin,
                _roles.bridgeAdapterManager,
                _roles.cacheManager,
                SLIPPAGE_CAP_PCT,
                BRIDGE_CACHE_MAX_SIZE,
                _roles.claimer,
                _fork.tokenMessengerV2,
                _fork.usdc
            )
        );

        CCTPv2BridgeAdapter adapter = CCTPv2BridgeAdapter(payable(address(proxy)));
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
        uint64 randomNonce = uint64(uint256(keccak256(abi.encode(block.timestamp, block.number, message, msg.sender))));
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
        require(
            finalityThreshold >= MIN_FINALITY_THRESHOLD && finalityThreshold <= MAX_FINALITY_THRESHOLD,
            "threshold out of range"
        );
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
