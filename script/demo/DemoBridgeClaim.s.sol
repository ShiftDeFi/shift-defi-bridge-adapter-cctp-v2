// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {CCTPv2BridgeAdapter} from "contracts/CCTPv2BridgeAdapter.sol";

/// @notice Demo script: run against the destination chain to submit the CCTP message +
/// attestation (from Circle's Iris API), then withdraw the claimed USDC into the receiver's wallet.
/// @dev Broadcaster must hold CLAIMER_ROLE on `BRIDGE_ADAPTER`. claim() pays out to msg.sender, so
/// the broadcaster must also be the receiver encoded in BRIDGE_MESSAGE for the withdraw to succeed.
/// Paste a fresh message/attestation pair from the Iris API before each run.
contract DemoBridgeClaimScript is Script {
    bytes private constant BRIDGE_MESSAGE =
        hex"000000010000000000000006d968908f5c0fd938f857dd181275e63f73efe422256cb856e4ea06e7f1107b0e00000000000000000000000028b5a0e9c621a5badaa536219b3a228c8168cf5d00000000000000000000000028b5a0e9c621a5badaa536219b3a228c8168cf5d00000000000000000000000090c57d8a3f51cc7a6c6c4215ad28457781a96b4b000007d0000007d000000001000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000090c57d8a3f51cc7a6c6c4215ad28457781a96b4b00000000000000000000000000000000000000000000000000000000001e84800000000000000000000000000819ecf5826495b5c32242cb3273f48d9ae05138000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000df2b1f368b9ab6cea6d0187b6108d18ee7a3b5a3";

    bytes private constant BRIDGE_ATTESTATION =
        hex"e551b0b04285a5c11d74d903c4f98abfd27fbe5eb13406d04dd62383ef910d6d4ff1f61d299cf2ed5c38baf65a720160a304805aa8d0d508d21cd7a4f17915ba1c1a3be97ff9598b215ea6004298b0c2d8aa7d86a41a18749a49838a75039407677f81a71c19a0580d1691c477e2f34b53451b4186aa386c9d9f90252cce9053ca1c";

    function run() public {
        CCTPv2BridgeAdapter adapter = CCTPv2BridgeAdapter(payable(vm.envAddress("BRIDGE_ADAPTER_DST")));
        address usdc = vm.envAddress("USDC_DST");

        vm.startBroadcast();
        adapter.claimCCTPBridge(BRIDGE_MESSAGE, BRIDGE_ATTESTATION);
        uint256 amount = adapter.claim(usdc);
        vm.stopBroadcast();

        console.log("Bridge message claimed on %s", address(adapter));
        console.log("Withdrawn %s USDC to the broadcaster's wallet", amount);
    }
}
