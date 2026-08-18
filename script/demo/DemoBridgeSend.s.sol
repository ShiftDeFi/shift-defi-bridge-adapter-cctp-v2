// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IBridgeAdapter} from "@shift-defi/core/contracts/interfaces/IBridgeAdapter.sol";

import {CCTPv2BridgeAdapter} from "contracts/CCTPv2BridgeAdapter.sol";

/// @notice Demo script: run against the source chain to burn USDC via CCTP through the bridge adapter.
/// @dev Broadcaster must already be whitelisted as a bridger on `BRIDGE_ADAPTER` and hold `AMOUNT` of USDC.
/// Defaults to a CCTP fast transfer (fee set via FAST_TRANSFER_FEE_PPM, soft finality); set
/// REGULAR_TRANSFER=true for a free standard transfer (hard finality) instead. The fast-transfer
/// fee is not constant across chains and can be fractional in bps (e.g. Base's 1.3 bps), so it's
/// expressed in parts-per-million (bps * 100) and supplied per run rather than hardcoded.
contract DemoBridgeSendScript is Script {
    uint256 private constant PPM_DENOMINATOR = 1_000_000;

    uint32 private constant FAST_TRANSFER_FINALITY_THRESHOLD = 1000;
    uint32 private constant STANDARD_TRANSFER_FINALITY_THRESHOLD = 2000;

    function run() public {
        CCTPv2BridgeAdapter adapter = CCTPv2BridgeAdapter(payable(vm.envAddress("BRIDGE_ADAPTER_SRC")));
        address usdc = vm.envAddress("USDC_SRC");
        uint256 destChainId = vm.envUint("DST_CHAIN_ID");
        address receiver = vm.envAddress("RECEIVER");
        uint256 amount = vm.envUint("AMOUNT");

        bool isFastTransfer = !vm.envOr("REGULAR_TRANSFER", false);
        uint256 maxFee = isFastTransfer ? Math.mulDiv(amount, vm.envUint("FAST_TRANSFER_FEE_PPM"), PPM_DENOMINATOR) : 0;
        uint256 minTokenAmount = amount - maxFee;
        uint32 minFinalityThreshold = isFastTransfer
            ? FAST_TRANSFER_FINALITY_THRESHOLD
            : STANDARD_TRANSFER_FINALITY_THRESHOLD;

        bytes memory payload = adapter.encodeCCTPV2Payload(maxFee, minFinalityThreshold);

        IBridgeAdapter.BridgeInstruction memory instruction = IBridgeAdapter.BridgeInstruction({
            value: 0,
            chainTo: destChainId,
            amount: amount,
            minTokenAmount: minTokenAmount,
            token: usdc,
            payload: payload
        });

        vm.startBroadcast();
        IERC20(usdc).approve(address(adapter), amount);
        uint256 bridgedAmount = adapter.bridge(instruction, receiver);
        vm.stopBroadcast();

        console.log(isFastTransfer ? "Transfer type: fast" : "Transfer type: regular");
        console.log("Max fee: %s", maxFee);
        console.log("Bridged amount (after max fee): %s", bridgedAmount);
        console.log("Receiver on destination chain: %s", receiver);
    }
}
