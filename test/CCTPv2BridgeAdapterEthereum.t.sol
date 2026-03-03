import {CCTPv2BridgeAdapterTest} from "./CCTPv2BridgeAdapter.t.sol";

contract CCTPv2BridgeAdapterEthereumTest is CCTPv2BridgeAdapterTest {
    address constant ETHEREUM_TOKEN_MESSENGER_V2 = 0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d;
    address constant ARBITRUM_TOKEN_MESSENGER_V2 = 0x28b5a0e9C621a5BadaA536219b3a228C8168cf5d;

    address constant ETHEREUM_USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant ARBITRUM_USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831;

    uint256 constant ETHEREUM_CHAIN_ID = 1;
    uint256 constant ARBITRUM_CHAIN_ID = 42161;

    uint32 constant ETHEREUM_DOMAIN_ID = 0;
    uint32 constant ARBITRUM_DOMAIN_ID = 3;

    function setUp() public {
        string memory ETHEREUM_RPC = vm.envString("ETH_RPC_URL");
        string memory ARBITRUM_RPC = vm.envString("ARB_RPC_URL");

        Fork memory l1Fork = Fork({
            rpc: ETHEREUM_RPC,
            tokenMessengerV2: ETHEREUM_TOKEN_MESSENGER_V2,
            usdc: ETHEREUM_USDC,
            chainId: ETHEREUM_CHAIN_ID,
            domainId: ETHEREUM_DOMAIN_ID
        });
        Fork memory l2Fork = Fork({
            rpc: ARBITRUM_RPC,
            tokenMessengerV2: ARBITRUM_TOKEN_MESSENGER_V2,
            usdc: ARBITRUM_USDC,
            chainId: ARBITRUM_CHAIN_ID,
            domainId: ARBITRUM_DOMAIN_ID
        });
        _setUp(l1Fork, l2Fork);
    }
}
