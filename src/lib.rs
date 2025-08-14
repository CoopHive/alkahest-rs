use alloy::{
    primitives::{Address, FixedBytes, Log},
    providers::Provider,
    rpc::types::{Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use extensions::{AlkahestExtension, BaseExtensions};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sol_types::EscrowClaimed;
use types::{PublicProvider, WalletProvider};

use crate::clients::{
    arbiters::ArbitersAddresses, attestation::AttestationAddresses, erc20::Erc20Addresses,
    erc721::Erc721Addresses, erc1155::Erc1155Addresses,
    string_obligation::StringObligationAddresses, token_bundle::TokenBundleAddresses,
};

/// Type alias for the default AlkahestClient with BaseExtensions
pub type DefaultAlkahestClient = AlkahestClient<BaseExtensions>;

pub mod addresses;
pub mod clients;
pub mod contracts;
pub mod extensions;
pub mod fixtures;
pub mod registry;
pub mod sol_types;
pub mod types;
pub mod utils;

// Re-export registry types for convenience
pub use registry::{
    ArbitersContract, AttestationContract, ContractModule, Erc20Contract, Erc721Contract,
    Erc1155Contract, StringObligationContract, TokenBundleContract,
};

/// Configuration struct containing all contract addresses for Alkahest protocol extensions.
///
/// This struct holds the addresses for all the smart contracts used by different
/// protocol modules. Each field represents a different module's addresses.
///
/// # Default Behavior
///
/// When using `Default::default()` or passing `None` to client constructors,
/// the Base Sepolia network addresses are used by default.
///
/// # Example
///
/// ```rust,ignore
/// use alkahest_rs::{DefaultExtensionConfig, addresses::BASE_SEPOLIA_ADDRESSES};
///
/// // Use default (Base Sepolia) configuration
/// let default_config = DefaultExtensionConfig::default();
///
/// // Use a predefined configuration
/// let base_config = BASE_SEPOLIA_ADDRESSES;
///
/// // Create a custom configuration
/// let custom_config = DefaultExtensionConfig {
///     arbiters_addresses: my_custom_arbiters,
///     erc20_addresses: my_custom_erc20,
///     // ... other fields
///     ..BASE_SEPOLIA_ADDRESSES
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultExtensionConfig {
    /// Addresses for arbiter contracts that handle obligation verification
    pub arbiters_addresses: ArbitersAddresses,
    /// Addresses for ERC20-related contracts
    pub erc20_addresses: Erc20Addresses,
    /// Addresses for ERC721-related contracts
    pub erc721_addresses: Erc721Addresses,
    /// Addresses for ERC1155-related contracts
    pub erc1155_addresses: Erc1155Addresses,
    /// Addresses for token bundle contracts that handle multiple token types
    pub token_bundle_addresses: TokenBundleAddresses,
    /// Addresses for attestation-related contracts
    pub attestation_addresses: AttestationAddresses,
    /// Addresses for string obligation contracts
    pub string_obligation_addresses: StringObligationAddresses,
}

impl Default for DefaultExtensionConfig {
    /// Returns the default configuration using Base Sepolia network addresses.
    ///
    /// This is equivalent to using `BASE_SEPOLIA_ADDRESSES` directly.
    fn default() -> Self {
        // Use Base Sepolia as the default network
        crate::addresses::BASE_SEPOLIA_ADDRESSES
    }
}

#[derive(Clone)]
pub struct AlkahestClient<Extensions: AlkahestExtension = BaseExtensions> {
    pub wallet_provider: WalletProvider,
    pub public_provider: PublicProvider,
    pub address: Address,
    pub extensions: Extensions,
    private_key: PrivateKeySigner,
    rpc_url: String,
    extension_configs:
        std::collections::HashMap<String, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
}

impl<Extensions: AlkahestExtension> AlkahestClient<Extensions> {
    pub async fn new(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<DefaultExtensionConfig>,
    ) -> eyre::Result<Self> {
        let wallet_provider =
            utils::get_wallet_provider(private_key.clone(), rpc_url.clone()).await?;
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;

        let extensions = Extensions::init(private_key.clone(), rpc_url.clone(), addresses).await?;

        Ok(AlkahestClient {
            wallet_provider,
            public_provider,
            address: private_key.address(),
            extensions,
            private_key,
            rpc_url: rpc_url.to_string(),
            extension_configs: std::collections::HashMap::new(),
        })
    }

    /// Add an extension using a custom config type
    pub async fn with_extension<NewExt: AlkahestExtension, A: Clone + Send + Sync + 'static>(
        mut self,
        config: Option<A>,
    ) -> eyre::Result<AlkahestClient<extensions::JoinExtension<Extensions, NewExt>>> {
        // Store the config for later use if provided
        if let Some(ref cfg) = config {
            let type_name = std::any::type_name::<NewExt>().to_string();
            self.extension_configs
                .insert(type_name, std::sync::Arc::new(cfg.clone()));
        }

        let new_extension =
            NewExt::init_with_config(self.private_key.clone(), self.rpc_url.clone(), config)
                .await?;

        let joined_extensions = extensions::JoinExtension {
            left: self.extensions,
            right: new_extension,
        };

        Ok(AlkahestClient {
            wallet_provider: self.wallet_provider,
            public_provider: self.public_provider,
            address: self.address,
            extensions: joined_extensions,
            private_key: self.private_key,
            rpc_url: self.rpc_url,
            extension_configs: self.extension_configs,
        })
    }

    /// Add an already initialized extension to the current client
    pub fn with_initialized_extension<NewExt: AlkahestExtension>(
        self,
        extension: NewExt,
    ) -> AlkahestClient<extensions::JoinExtension<Extensions, NewExt>> {
        let joined_extensions = extensions::JoinExtension {
            left: self.extensions,
            right: extension,
        };

        AlkahestClient {
            wallet_provider: self.wallet_provider,
            public_provider: self.public_provider,
            address: self.address,
            extensions: joined_extensions,
            private_key: self.private_key,
            rpc_url: self.rpc_url,
            extension_configs: self.extension_configs,
        }
    }

    /// Get the stored configuration for a specific extension type
    pub fn get_extension_config<Ext: AlkahestExtension, A: Clone + Send + Sync + 'static>(
        &self,
    ) -> Option<&A> {
        let type_name = std::any::type_name::<Ext>();
        self.extension_configs
            .get(type_name)
            .and_then(|arc| arc.downcast_ref::<A>())
    }

    /// Check if a configuration exists for a specific extension type
    pub fn has_extension_config<Ext: AlkahestExtension>(&self) -> bool {
        let type_name = std::any::type_name::<Ext>();
        self.extension_configs.contains_key(type_name)
    }

    /// Extracts an Attested event from a transaction receipt.
    ///
    /// # Arguments
    /// * `receipt` - The transaction receipt to extract the event from
    ///
    /// # Returns
    /// * `Result<Log<Attested>>` - The decoded Attested event log
    pub fn get_attested_event(
        receipt: TransactionReceipt,
    ) -> eyre::Result<Log<contracts::IEAS::Attested>> {
        let attested_event = receipt
            .inner
            .logs()
            .iter()
            .filter(|log| log.topic0() == Some(&contracts::IEAS::Attested::SIGNATURE_HASH))
            .collect::<Vec<_>>()
            .first()
            .map(|log| log.log_decode::<contracts::IEAS::Attested>())
            .ok_or_else(|| eyre::eyre!("No Attested event found"))??;

        Ok(attested_event.inner)
    }

    /// Waits for a fulfillment event for a specific escrow arrangement.
    ///
    /// This function will:
    /// 1. Check for existing fulfillment events from the specified block
    /// 2. If none found, subscribe to new events and wait for fulfillment
    ///
    /// # Arguments
    /// * `contract_address` - The address of the contract to monitor
    /// * `buy_attestation` - The attestation UID of the buy order
    /// * `from_block` - Optional block number to start searching from
    ///
    /// # Returns
    /// * `Result<Log<EscrowClaimed>>` - The fulfillment event log when found
    pub async fn wait_for_fulfillment(
        &self,
        contract_address: Address,
        buy_attestation: FixedBytes<32>,
        from_block: Option<u64>,
    ) -> eyre::Result<Log<EscrowClaimed>> {
        let filter = Filter::new()
            .from_block(from_block.unwrap_or(0))
            .address(contract_address)
            .event_signature(EscrowClaimed::SIGNATURE_HASH)
            .topic1(buy_attestation);

        let logs = self.public_provider.get_logs(&filter).await?;
        println!("initial logs: {:?}", logs);
        if let Some(log) = logs
            .iter()
            .collect::<Vec<_>>()
            .first()
            .map(|log| log.log_decode::<EscrowClaimed>())
        {
            return Ok(log?.inner);
        }

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        if let Some(log) = stream.next().await {
            let log = log.log_decode::<EscrowClaimed>()?;
            return Ok(log.inner);
        }

        Err(eyre::eyre!("No EscrowClaimed event found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addresses::{BASE_SEPOLIA_ADDRESSES, FILECOIN_CALIBRATION_ADDRESSES};

    #[test]
    fn test_default_extension_config_uses_base_sepolia() {
        let default_config = DefaultExtensionConfig::default();

        // Verify that default configuration matches BASE_SEPOLIA_ADDRESSES
        assert_eq!(
            default_config.arbiters_addresses.eas,
            BASE_SEPOLIA_ADDRESSES.arbiters_addresses.eas
        );
        assert_eq!(
            default_config.erc20_addresses.barter_utils,
            BASE_SEPOLIA_ADDRESSES.erc20_addresses.barter_utils
        );
        assert_eq!(
            default_config.attestation_addresses.eas,
            BASE_SEPOLIA_ADDRESSES.attestation_addresses.eas
        );
    }

    #[test]
    fn test_config_clone() {
        let config = DefaultExtensionConfig::default();
        let cloned = config.clone();

        assert_eq!(config.arbiters_addresses.eas, cloned.arbiters_addresses.eas);
        assert_eq!(
            config.erc20_addresses.barter_utils,
            cloned.erc20_addresses.barter_utils
        );
    }

    #[test]
    fn test_custom_config_with_struct_update_syntax() {
        let custom_config = DefaultExtensionConfig {
            arbiters_addresses: FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses,
            ..BASE_SEPOLIA_ADDRESSES
        };

        // Verify arbiter addresses are from Filecoin
        assert_eq!(
            custom_config.arbiters_addresses.eas,
            FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses.eas
        );

        // Verify other addresses are still from Base Sepolia
        assert_eq!(
            custom_config.erc20_addresses.eas,
            BASE_SEPOLIA_ADDRESSES.erc20_addresses.eas
        );
    }

    #[test]
    fn test_all_address_fields_populated() {
        let config = DefaultExtensionConfig::default();

        // Test that no address is zero (all fields should be populated)
        assert_ne!(config.arbiters_addresses.eas, Address::ZERO);
        assert_ne!(config.erc20_addresses.eas, Address::ZERO);
        assert_ne!(config.erc721_addresses.eas, Address::ZERO);
        assert_ne!(config.erc1155_addresses.eas, Address::ZERO);
        assert_ne!(config.token_bundle_addresses.eas, Address::ZERO);
        assert_ne!(config.attestation_addresses.eas, Address::ZERO);

        // Test specific contract addresses
        assert_ne!(config.erc20_addresses.barter_utils, Address::ZERO);
        assert_ne!(config.erc20_addresses.escrow_obligation, Address::ZERO);
        assert_ne!(config.erc20_addresses.payment_obligation, Address::ZERO);
    }

    #[test]
    fn test_serialize_deserialize_default_extension_config() {
        let original_config = DefaultExtensionConfig::default();

        // Serialize to JSON
        let json = serde_json::to_string(&original_config).expect("Failed to serialize");

        // Deserialize from JSON
        let deserialized_config: DefaultExtensionConfig =
            serde_json::from_str(&json).expect("Failed to deserialize");

        // Verify all fields match
        assert_eq!(
            original_config.arbiters_addresses.eas,
            deserialized_config.arbiters_addresses.eas
        );
        assert_eq!(
            original_config.arbiters_addresses.trusted_party_arbiter,
            deserialized_config.arbiters_addresses.trusted_party_arbiter
        );
        assert_eq!(
            original_config.erc20_addresses.eas,
            deserialized_config.erc20_addresses.eas
        );
        assert_eq!(
            original_config.erc20_addresses.barter_utils,
            deserialized_config.erc20_addresses.barter_utils
        );
        assert_eq!(
            original_config.erc721_addresses.eas,
            deserialized_config.erc721_addresses.eas
        );
        assert_eq!(
            original_config.erc1155_addresses.eas,
            deserialized_config.erc1155_addresses.eas
        );
        assert_eq!(
            original_config.token_bundle_addresses.eas,
            deserialized_config.token_bundle_addresses.eas
        );
        assert_eq!(
            original_config.attestation_addresses.eas,
            deserialized_config.attestation_addresses.eas
        );
        assert_eq!(
            original_config.string_obligation_addresses.eas,
            deserialized_config.string_obligation_addresses.eas
        );
    }

    #[test]
    fn test_serialize_custom_config() {
        // Create a custom config mixing addresses from different networks
        let custom_config = DefaultExtensionConfig {
            arbiters_addresses: FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses,
            erc20_addresses: BASE_SEPOLIA_ADDRESSES.erc20_addresses,
            ..FILECOIN_CALIBRATION_ADDRESSES
        };

        // Serialize to JSON
        let json = serde_json::to_string(&custom_config).expect("Failed to serialize");

        // Deserialize from JSON
        let deserialized_config: DefaultExtensionConfig =
            serde_json::from_str(&json).expect("Failed to deserialize");

        // Verify mixed addresses are preserved
        assert_eq!(
            custom_config.arbiters_addresses.eas,
            deserialized_config.arbiters_addresses.eas
        );
        assert_eq!(
            FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses.eas,
            deserialized_config.arbiters_addresses.eas
        );
        assert_eq!(
            custom_config.erc20_addresses.eas,
            deserialized_config.erc20_addresses.eas
        );
        assert_eq!(
            BASE_SEPOLIA_ADDRESSES.erc20_addresses.eas,
            deserialized_config.erc20_addresses.eas
        );
    }

    #[test]
    fn test_json_roundtrip_preserves_all_fields() {
        let config = BASE_SEPOLIA_ADDRESSES;

        // Convert to JSON and back
        let json = serde_json::to_value(&config).expect("Failed to serialize to value");
        let roundtrip_config: DefaultExtensionConfig =
            serde_json::from_value(json).expect("Failed to deserialize from value");

        // Comprehensive field checks
        // Arbiters addresses
        assert_eq!(
            config.arbiters_addresses.eas,
            roundtrip_config.arbiters_addresses.eas
        );
        assert_eq!(
            config.arbiters_addresses.trusted_party_arbiter,
            roundtrip_config.arbiters_addresses.trusted_party_arbiter
        );
        assert_eq!(
            config.arbiters_addresses.trivial_arbiter,
            roundtrip_config.arbiters_addresses.trivial_arbiter
        );

        // ERC20 addresses
        assert_eq!(
            config.erc20_addresses.eas,
            roundtrip_config.erc20_addresses.eas
        );
        assert_eq!(
            config.erc20_addresses.barter_utils,
            roundtrip_config.erc20_addresses.barter_utils
        );
        assert_eq!(
            config.erc20_addresses.escrow_obligation,
            roundtrip_config.erc20_addresses.escrow_obligation
        );
        assert_eq!(
            config.erc20_addresses.payment_obligation,
            roundtrip_config.erc20_addresses.payment_obligation
        );

        // ERC721 addresses
        assert_eq!(
            config.erc721_addresses.eas,
            roundtrip_config.erc721_addresses.eas
        );
        assert_eq!(
            config.erc721_addresses.barter_utils,
            roundtrip_config.erc721_addresses.barter_utils
        );

        // ERC1155 addresses
        assert_eq!(
            config.erc1155_addresses.eas,
            roundtrip_config.erc1155_addresses.eas
        );
        assert_eq!(
            config.erc1155_addresses.barter_utils,
            roundtrip_config.erc1155_addresses.barter_utils
        );

        // Token bundle addresses
        assert_eq!(
            config.token_bundle_addresses.eas,
            roundtrip_config.token_bundle_addresses.eas
        );
        assert_eq!(
            config.token_bundle_addresses.barter_utils,
            roundtrip_config.token_bundle_addresses.barter_utils
        );

        // Attestation addresses
        assert_eq!(
            config.attestation_addresses.eas,
            roundtrip_config.attestation_addresses.eas
        );
        assert_eq!(
            config.attestation_addresses.eas_schema_registry,
            roundtrip_config.attestation_addresses.eas_schema_registry
        );

        // String obligation addresses
        assert_eq!(
            config.string_obligation_addresses.eas,
            roundtrip_config.string_obligation_addresses.eas
        );
        assert_eq!(
            config.string_obligation_addresses.obligation,
            roundtrip_config.string_obligation_addresses.obligation
        );
    }
}
