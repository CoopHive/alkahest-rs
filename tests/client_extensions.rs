use std::env;

use alkahest_rs::{
    AlkahestClient, DefaultExtensionConfig,
    clients::erc20::{Erc20Addresses, Erc20Client},
    extensions::{AlkahestExtension, Erc20Module, HasErc20, NoExtension},
};
use alloy::{primitives::address, signers::local::PrivateKeySigner};
use eyre::Result;
use serial_test::serial;

// Custom extension for testing
#[derive(Clone)]
pub struct CustomTrackerExtension {
    pub client: CustomTrackerClient,
}

#[derive(Clone)]
pub struct CustomTrackerClient {
    pub name: String,
    pub counter: u64,
    pub metadata: Option<String>,
}

#[derive(Clone)]
pub struct CustomTrackerConfig {
    pub name: String,
    pub initial_counter: u64,
    pub metadata: Option<String>,
}

impl CustomTrackerClient {
    pub fn new(config: Option<CustomTrackerConfig>) -> Self {
        let config = config.unwrap_or_else(|| CustomTrackerConfig {
            name: "default_tracker".to_string(),
            initial_counter: 0,
            metadata: None,
        });

        Self {
            name: config.name,
            counter: config.initial_counter,
            metadata: config.metadata,
        }
    }

    pub fn increment(&mut self) {
        self.counter += 1;
    }

    pub fn get_counter(&self) -> u64 {
        self.counter
    }

    pub fn set_metadata(&mut self, metadata: String) {
        self.metadata = Some(metadata);
    }
}

impl AlkahestExtension for CustomTrackerExtension {
    type Client = CustomTrackerClient;

    async fn init(
        _private_key: PrivateKeySigner,
        _rpc_url: impl ToString + Clone + Send,
        _config: Option<DefaultExtensionConfig>,
    ) -> eyre::Result<Self> {
        let client = CustomTrackerClient::new(None);
        Ok(CustomTrackerExtension { client })
    }

    async fn init_with_config<A: Clone + Send + Sync + 'static>(
        _private_key: PrivateKeySigner,
        _rpc_url: impl ToString + Clone + Send,
        config: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to CustomTrackerConfig
        let config = if let Some(addr) = config {
            let addr_any: &dyn std::any::Any = &addr;
            if let Some(tracker_config) = addr_any.downcast_ref::<CustomTrackerConfig>() {
                Some(tracker_config.clone())
            } else {
                None
            }
        } else {
            None
        };

        let client = CustomTrackerClient::new(config);
        Ok(CustomTrackerExtension { client })
    }

    fn client(&self) -> Option<&Self::Client> {
        Some(&self.client)
    }
}

// // Trait for accessing the custom tracker
// pub trait HasCustomTracker {
//     fn custom_tracker(&self) -> &CustomTrackerClient;
// }

// impl<T: AlkahestExtension> HasCustomTracker for AlkahestClient<T>
// where
//     T: AlkahestExtension,
//     T::Client: Clone + Send + Sync + 'static,
// {
//     fn custom_tracker(&self) -> &CustomTrackerClient {
//         self.extensions.get_client::<CustomTrackerClient>()
//     }
// }

/// Test using custom tracker extension with mutating operations
#[tokio::test]
#[serial]
async fn test_custom_tracker_extension() -> Result<()> {
    let private_key: PrivateKeySigner = env::var("PRIVKEY_ALICE")
        .unwrap_or_else(|_| {
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string()
        })
        .parse()?;

    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| "ws://localhost:8545".to_string());

    // Create custom tracker config with initial values
    let custom_config = CustomTrackerConfig {
        name: "mutation_tracker".to_string(),
        initial_counter: 10,
        metadata: None,
    };

    // Start with a client that has no extensions
    let client = AlkahestClient::<NoExtension>::new(private_key.clone(), &rpc_url, None).await?;

    // Add custom tracker extension with custom config
    let client_with_tracker = client
        .with_extension::<CustomTrackerExtension, CustomTrackerConfig>(Some(custom_config.clone()))
        .await?;

    // Test initial state
    assert_eq!(
        client_with_tracker
            .extensions
            .get_client::<CustomTrackerClient>()
            .get_counter(),
        10
    );
    assert_eq!(
        client_with_tracker
            .extensions
            .get_client::<CustomTrackerClient>()
            .metadata,
        None
    );

    Ok(())
}

/// Test using ERC20 extension with custom addresses (original test)
#[tokio::test]
#[serial]
async fn test_client_with_extension() -> Result<()> {
    let private_key: PrivateKeySigner = env::var("PRIVKEY_ALICE")
        .unwrap_or_else(|_| {
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string()
        })
        .parse()?;

    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| "ws://localhost:8545".to_string());

    // Create custom ERC20 addresses
    let custom_erc20_addresses = Erc20Addresses {
        eas: address!("0x1234567890123456789012345678901234567890"),
        payment_obligation: address!("0x2345678901234567890123456789012345678901"),
        escrow_obligation: address!("0x3456789012345678901234567890123456789012"),
        barter_utils: address!("0x4567890123456789012345678901234567890123"),
    };

    // Start with a client that has no extensions
    let client = AlkahestClient::<NoExtension>::new(private_key.clone(), &rpc_url, None).await?;

    // Add ERC20 extension with custom addresses
    let client_with_erc20 = client
        .with_extension::<Erc20Module, Erc20Addresses>(Some(custom_erc20_addresses.clone()))
        .await?;

    // Verify the custom addresses are used
    let erc20_client = client_with_erc20.erc20();
    assert_eq!(erc20_client.addresses.eas, custom_erc20_addresses.eas);
    assert_eq!(
        erc20_client.addresses.payment_obligation,
        custom_erc20_addresses.payment_obligation
    );
    assert_eq!(
        erc20_client.addresses.escrow_obligation,
        custom_erc20_addresses.escrow_obligation
    );
    assert_eq!(
        erc20_client.addresses.barter_utils,
        custom_erc20_addresses.barter_utils
    );

    Ok(())
}

/// Test using with_initialized_extension method (original test)
#[tokio::test]
#[serial]
async fn test_client_with_initialized_extension() -> Result<()> {
    let private_key: PrivateKeySigner = env::var("PRIVKEY_ALICE")
        .unwrap_or_else(|_| {
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string()
        })
        .parse()?;

    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| "ws://localhost:8545".to_string());

    // Create client with no extensions
    let client = AlkahestClient::<NoExtension>::new(private_key.clone(), &rpc_url, None).await?;

    // Initialize an extension separately
    let erc20_extension = Erc20Module::init(private_key.clone(), &rpc_url, None).await?;

    // Add the pre-initialized extension
    let client_with_erc20 = client.with_initialized_extension(erc20_extension);

    // Verify the extension was added
    assert!(client_with_erc20.extensions.has_client::<Erc20Client>());

    // Test accessing the client
    let _erc20_client = client_with_erc20.erc20();

    Ok(())
}
