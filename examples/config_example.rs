use alkahest_rs::{
    AlkahestClient, DefaultAlkahestClient, DefaultExtensionConfig,
    addresses::{BASE_SEPOLIA_ADDRESSES, FILECOIN_CALIBRATION_ADDRESSES},
    clients::{
        arbiters::ArbitersAddresses, attestation::AttestationAddresses, erc20::Erc20Addresses,
        erc721::Erc721Addresses, erc1155::Erc1155Addresses,
        string_obligation::StringObligationAddresses, token_bundle::TokenBundleAddresses,
    },
};
use alloy::primitives::address;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::PrivateKeySigner;
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Example 1: Using the default configuration (Base Sepolia)
    println!("Example 1: Using default configuration");
    let private_key = PrivateKeySigner::random();
    let rpc_url = "https://sepolia.base.org";

    // When None is passed, the default (Base Sepolia) addresses are used
    let client_with_default: DefaultAlkahestClient =
        AlkahestClient::new(private_key.clone(), rpc_url, None).await?;
    println!("Created client with default Base Sepolia addresses");

    // Example 2: Explicitly using Base Sepolia configuration
    println!("\nExample 2: Explicitly using Base Sepolia configuration");
    let client_with_base: DefaultAlkahestClient =
        AlkahestClient::new(private_key.clone(), rpc_url, Some(BASE_SEPOLIA_ADDRESSES)).await?;
    println!("Created client with explicit Base Sepolia addresses");

    // Example 3: Using Filecoin Calibration configuration
    println!("\nExample 3: Using Filecoin Calibration configuration");
    let filecoin_rpc_url = "https://api.calibration.node.glif.io/rpc/v1";
    let client_with_filecoin: DefaultAlkahestClient = AlkahestClient::new(
        private_key.clone(),
        filecoin_rpc_url,
        Some(FILECOIN_CALIBRATION_ADDRESSES),
    )
    .await?;
    println!("Created client with Filecoin Calibration addresses");

    // Example 4: Creating a custom configuration
    println!("\nExample 4: Creating custom configuration");
    let custom_config = DefaultExtensionConfig {
        arbiters_addresses: ArbitersAddresses {
            eas: address!("0x4200000000000000000000000000000000000021"),
            specific_attestation_arbiter: address!("0xdE5eCFC92E3da87865CD29C196aA5cebFdC4D9C6"),
            trusted_party_arbiter: address!("0x3895398C46da88b75eE3ca3092F7714BEbE795a5"),
            trivial_arbiter: address!("0x7D4bCD84901cEC903105564f63BE70432448B222"),
            // ... other arbiter addresses (using defaults for brevity)
            ..BASE_SEPOLIA_ADDRESSES.arbiters_addresses
        },
        erc20_addresses: Erc20Addresses {
            eas: address!("0x4200000000000000000000000000000000000021"),
            barter_utils: address!("0x5C624f8FbbB377378cDfE8B627384A917FE839db"),
            escrow_obligation: address!("0xFa76421cEe6aee41adc7f6a475b9Ef3776d500F0"),
            payment_obligation: address!("0xE95d3931E15E4d96cE1d2Dd336DcEad35A708bdB"),
        },
        // Using defaults for other address types
        erc721_addresses: BASE_SEPOLIA_ADDRESSES.erc721_addresses,
        erc1155_addresses: BASE_SEPOLIA_ADDRESSES.erc1155_addresses,
        token_bundle_addresses: BASE_SEPOLIA_ADDRESSES.token_bundle_addresses,
        attestation_addresses: BASE_SEPOLIA_ADDRESSES.attestation_addresses,
        string_obligation_addresses: BASE_SEPOLIA_ADDRESSES.string_obligation_addresses,
    };

    let client_with_custom: DefaultAlkahestClient =
        AlkahestClient::new(private_key.clone(), rpc_url, Some(custom_config)).await?;
    println!("Created client with custom configuration");

    // Example 5: Using Default::default() to get Base Sepolia configuration
    println!("\nExample 5: Using Default trait");
    let default_config = DefaultExtensionConfig::default();
    let client_with_default_trait: DefaultAlkahestClient =
        AlkahestClient::new(private_key, rpc_url, Some(default_config)).await?;
    println!("Created client using Default trait (equivalent to Base Sepolia)");

    println!("\nAll examples completed successfully!");
    Ok(())
}
