// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {CCTPv2BridgeAdapter} from "../../contracts/CCTPv2BridgeAdapter.sol";

import {Script} from "forge-std/Script.sol";

struct Roles {
    address deployer;
    address proxyAdminOwner;
    address defaultAdmin;
    address bridgeAdapterManager;
    address cacheManager;
    address claimer;
}

contract DeployCCTPv2BridgeAdapterScript is Script {
    Roles public roles;

    address public USDC;
    address public TOKEN_MESSENGER_V2;
    uint256 public SLIPPAGE_CAP_PCT;
    uint256 public MAX_CACHE_SIZE;

    function _proxifyWithSalt(address implementation, bytes memory data) internal returns (address) {
        bytes32 saltHash = keccak256(abi.encodePacked(implementation, block.timestamp, block.chainid));
        return address(new TransparentUpgradeableProxy{salt: saltHash}(implementation, roles.proxyAdminOwner, data));
    }

    function _readRolesFromEnv() internal {
        roles.deployer = vm.envAddress("DEPLOYER");
        roles.proxyAdminOwner = vm.envAddress("PROXY_ADMIN_OWNER");
        roles.defaultAdmin = vm.envAddress("DEFAULT_ADMIN_ROLE");
        roles.bridgeAdapterManager = vm.envAddress("BRIDGE_ADAPTER_MANAGER_ROLE");
        roles.cacheManager = vm.envAddress("CACHE_MANAGER_ROLE");
        roles.claimer = vm.envAddress("CLAIMER_ROLE");
    }

    function run() public {
        _readRolesFromEnv();

        USDC = vm.envAddress("USDC");
        TOKEN_MESSENGER_V2 = vm.envAddress("TOKEN_MESSENGER_V2");
        SLIPPAGE_CAP_PCT = vm.envUint("SLIPPAGE_CAP_PCT");
        MAX_CACHE_SIZE = vm.envUint("MAX_CACHE_SIZE");

        vm.startBroadcast();
        address implementation = address(new CCTPv2BridgeAdapter());
        _proxifyWithSalt(
            implementation,
            abi.encodeWithSelector(
                CCTPv2BridgeAdapter.initialize.selector,
                roles.defaultAdmin,
                roles.bridgeAdapterManager,
                roles.cacheManager,
                SLIPPAGE_CAP_PCT,
                MAX_CACHE_SIZE,
                roles.claimer,
                TOKEN_MESSENGER_V2,
                USDC
            )
        );
        vm.stopBroadcast();
    }
}
