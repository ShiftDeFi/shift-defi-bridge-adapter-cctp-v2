// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {CCTPv2BridgeAdapter} from "contracts/CCTPv2BridgeAdapter.sol";

contract ConfigureCCTPv2BridgeAdapterScript is Script {
    CCTPv2BridgeAdapter public bridgeAdapter;

    address public USDC;
    uint256 public PEER_CHAIN_ID;
    address public PEER_BRIDGE_ADAPTER;
    address public PEER_USDC;
    uint32 public PEER_DOMAIN_ID;
    address[] public BRIDGERS;

    function _readConfigFromEnv() internal {
        bridgeAdapter = CCTPv2BridgeAdapter(payable(vm.envAddress("CCTP_V2_BRIDGE_ADAPTER_PROXY")));

        USDC = vm.envAddress("USDC");
        PEER_CHAIN_ID = vm.envUint("PEER_CHAIN_ID");
        PEER_BRIDGE_ADAPTER = vm.envAddress("PEER_BRIDGE_ADAPTER");
        PEER_USDC = vm.envAddress("PEER_USDC");
        PEER_DOMAIN_ID = uint32(vm.envUint("PEER_DOMAIN_ID"));
        BRIDGERS = vm.envAddress("BRIDGERS", ",");
    }

    function run() public {
        _readConfigFromEnv();

        vm.startBroadcast();

        bridgeAdapter.setBridgePath(USDC, PEER_CHAIN_ID, PEER_USDC);
        console.log("Bridge path set for USDC -> chain %s -> peer USDC %s", PEER_CHAIN_ID, PEER_USDC);

        bridgeAdapter.setPeer(PEER_CHAIN_ID, PEER_BRIDGE_ADAPTER);
        console.log("Peer set for chain %s: %s", PEER_CHAIN_ID, PEER_BRIDGE_ADAPTER);

        for (uint256 i = 0; i < BRIDGERS.length; ++i) {
            bridgeAdapter.whitelistBridger(BRIDGERS[i]);
            console.log("Bridger whitelisted: %s", BRIDGERS[i]);
        }

        bridgeAdapter.whitelistDomain(PEER_CHAIN_ID, PEER_DOMAIN_ID);
        console.log("Domain whitelisted for chain %s: domain id %s", PEER_CHAIN_ID, PEER_DOMAIN_ID);

        vm.stopBroadcast();
    }
}
