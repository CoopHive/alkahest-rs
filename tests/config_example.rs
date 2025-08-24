use alkahest_rs::{
    AlkahestClient, DefaultAlkahestClient, DefaultExtensionConfig,
    addresses::{BASE_SEPOLIA_ADDRESSES, FILECOIN_CALIBRATION_ADDRESSES},
    clients::{
        arbiters::ArbitersAddresses, attestation::AttestationAddresses, erc20::Erc20Addresses,
        erc721::Erc721Addresses, erc1155::Erc1155Addresses,
        string_obligation::StringObligationAddresses, token_bundle::TokenBundleAddresses,
    },
    extensions::{HasArbiters as _, HasErc20 as _, HasErc721 as _},
};
use alloy::primitives::address;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::local::PrivateKeySigner;
use eyre::Result;

#[tokio::test]
async fn test_default_configuration() -> Result<()> {
    // Test using the default configuration (Base Sepolia)
    let private_key = PrivateKeySigner::random();
    let rpc_url = "https://sepolia.base.org";

    // When None is passed, the default (Base Sepolia) addresses are used
    let client_with_default: DefaultAlkahestClient =
        AlkahestClient::with_base_extensions(private_key.clone(), rpc_url, None).await?;

    // Verify client was created successfully
    assert_ne!(
        client_with_default.address,
        alloy::primitives::Address::ZERO
    );

    // Verify it uses Base Sepolia addresses by default
    assert_eq!(
        client_with_default.erc20().addresses.eas,
        BASE_SEPOLIA_ADDRESSES.erc20_addresses.eas
    );

    Ok(())
}

#[tokio::test]
async fn test_explicit_base_sepolia_configuration() -> Result<()> {
    // Test explicitly using Base Sepolia configuration
    let private_key = PrivateKeySigner::random();
    let rpc_url = "https://sepolia.base.org";

    let client_with_base: DefaultAlkahestClient = AlkahestClient::with_base_extensions(
        private_key.clone(),
        rpc_url,
        Some(BASE_SEPOLIA_ADDRESSES),
    )
    .await?;

    // Verify the Base Sepolia addresses are used
    assert_eq!(
        client_with_base.erc20().addresses.eas,
        BASE_SEPOLIA_ADDRESSES.erc20_addresses.eas
    );
    assert_eq!(
        client_with_base.arbiters().addresses.eas,
        BASE_SEPOLIA_ADDRESSES.arbiters_addresses.eas
    );

    Ok(())
}

#[tokio::test]
async fn test_filecoin_calibration_configuration() -> Result<()> {
    // Test using Filecoin Calibration configuration
    let private_key = PrivateKeySigner::random();
    let filecoin_rpc_url = "https://api.calibration.node.glif.io/rpc/v1";

    let client_with_filecoin: DefaultAlkahestClient = AlkahestClient::with_base_extensions(
        private_key.clone(),
        filecoin_rpc_url,
        Some(FILECOIN_CALIBRATION_ADDRESSES),
    )
    .await?;

    // Verify Filecoin Calibration addresses are used
    assert_eq!(
        client_with_filecoin.erc20().addresses.eas,
        FILECOIN_CALIBRATION_ADDRESSES.erc20_addresses.eas
    );
    assert_eq!(
        client_with_filecoin.arbiters().addresses.eas,
        FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses.eas
    );

    // Verify they're different from Base Sepolia
    assert_ne!(
        client_with_filecoin.erc20().addresses.eas,
        BASE_SEPOLIA_ADDRESSES.erc20_addresses.eas
    );

    Ok(())
}

#[tokio::test]
async fn test_custom_configuration() -> Result<()> {
    // Test creating a custom configuration
    let private_key = PrivateKeySigner::random();
    let rpc_url = "https://sepolia.base.org";

    let custom_config = DefaultExtensionConfig {
        arbiters_addresses: ArbitersAddresses {
            eas: address!("0x4200000000000000000000000000000000000021"),
            specific_attestation_arbiter: address!("0xdE5eCFC92E3da87865CD29C196aA5cebFdC4D9C6"),
            trusted_party_arbiter: address!("0x3895398C46da88b75eE3ca3092F7714BEbE795a5"),
            trivial_arbiter: address!("0x7D4bCD84901cEC903105564f63BE70432448B222"),
            // Use defaults for other arbiter addresses
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

    let client_with_custom: DefaultAlkahestClient = AlkahestClient::with_base_extensions(
        private_key.clone(),
        rpc_url,
        Some(custom_config.clone()),
    )
    .await?;

    // Verify custom addresses are used
    assert_eq!(
        client_with_custom.erc20().addresses.eas,
        custom_config.erc20_addresses.eas
    );
    assert_eq!(
        client_with_custom.erc20().addresses.barter_utils,
        custom_config.erc20_addresses.barter_utils
    );
    assert_eq!(
        client_with_custom
            .arbiters()
            .addresses
            .trusted_party_arbiter,
        custom_config.arbiters_addresses.trusted_party_arbiter
    );

    // Verify that non-customized parts still use base addresses
    assert_eq!(
        client_with_custom.erc721().addresses.eas,
        BASE_SEPOLIA_ADDRESSES.erc721_addresses.eas
    );

    Ok(())
}

#[tokio::test]
async fn test_default_trait_configuration() -> Result<()> {
    // Test using Default::default() to get Base Sepolia configuration
    let private_key = PrivateKeySigner::random();
    let rpc_url = "https://sepolia.base.org";

    let default_config = DefaultExtensionConfig::default();
    let client_with_default_trait: DefaultAlkahestClient =
        AlkahestClient::with_base_extensions(private_key, rpc_url, Some(default_config.clone()))
            .await?;

    // Verify it uses Base Sepolia addresses (the default)
    assert_eq!(
        client_with_default_trait.erc20().addresses.eas,
        BASE_SEPOLIA_ADDRESSES.erc20_addresses.eas
    );
    assert_eq!(
        default_config.erc20_addresses.eas,
        BASE_SEPOLIA_ADDRESSES.erc20_addresses.eas
    );

    Ok(())
}

#[tokio::test]
async fn test_mixed_network_configuration() -> Result<()> {
    // Test mixing addresses from different networks
    let private_key = PrivateKeySigner::random();
    let rpc_url = "https://sepolia.base.org";

    // Create a config that mixes Filecoin arbiters with Base Sepolia ERC20
    let mixed_config = DefaultExtensionConfig {
        arbiters_addresses: FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses.clone(),
        erc20_addresses: BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone(),
        ..FILECOIN_CALIBRATION_ADDRESSES
    };

    let client_with_mixed: DefaultAlkahestClient =
        AlkahestClient::with_base_extensions(private_key, rpc_url, Some(mixed_config.clone()))
            .await?;

    // Verify the mixed configuration is applied correctly
    assert_eq!(
        client_with_mixed.arbiters().addresses.eas,
        FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses.eas
    );
    assert_eq!(
        client_with_mixed.erc20().addresses.eas,
        BASE_SEPOLIA_ADDRESSES.erc20_addresses.eas
    );

    // Verify they're different (since we mixed networks)
    assert_ne!(
        client_with_mixed.arbiters().addresses.eas,
        client_with_mixed.erc20().addresses.eas
    );

    Ok(())
}
