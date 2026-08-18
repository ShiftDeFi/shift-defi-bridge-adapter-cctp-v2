// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {CCTPv2BridgeAdapter} from "contracts/CCTPv2BridgeAdapter.sol";

contract UpgradeCCTPv2BridgeAdapter is Script {
    address private cctpV2BridgeAdapterProxy = vm.envAddress("CCTP_V2_BRIDGE_ADAPTER_PROXY");
    address private cctpV2BridgeAdapterProxyAdmin = vm.envAddress("CCTP_V2_BRIDGE_ADAPTER_PROXY_ADMIN");

    function run() public {
        bytes memory data = "";

        vm.startBroadcast();
        address newImplementation = address(new CCTPv2BridgeAdapter());
        vm.stopBroadcast();

        bytes memory dataToSign = abi.encodeCall(
            ProxyAdmin.upgradeAndCall,
            (ITransparentUpgradeableProxy(cctpV2BridgeAdapterProxy), newImplementation, data)
        );

        console.log("Data to sign:");
        console.logBytes(dataToSign);
    }
}
