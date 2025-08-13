use alkahest_rs::{
    AlkahestClient, DefaultExtensionConfig,
    clients::erc20::{Erc20Addresses, Erc20Client},
    extensions::{AlkahestExtension, Erc20Module, HasErc20, NoExtension},
    utils::setup_test_environment,
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

/// Test using custom tracker extension with mutating operations
#[tokio::test]
#[serial]
async fn test_custom_tracker_extension() -> Result<()> {
    let test_context = setup_test_environment().await?;

    // Get the RPC URL from the anvil instance
    let rpc_url = test_context.anvil.ws_endpoint();

    // Create custom tracker config with initial values
    let custom_config = CustomTrackerConfig {
        name: "mutation_tracker".to_string(),
        initial_counter: 10,
        metadata: None,
    };

    // Start with a client that has no extensions
    let client =
        AlkahestClient::<NoExtension>::new(test_context.alice.clone(), &rpc_url, None).await?;

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

/// Test retrieving stored extension config
#[tokio::test]
#[serial]
async fn test_get_extension_config() -> Result<()> {
    let test_context = setup_test_environment().await?;

    // Get the RPC URL from the anvil instance
    let rpc_url = test_context.anvil.ws_endpoint();

    // Create custom tracker config with initial values
    let custom_config = CustomTrackerConfig {
        name: "config_test_tracker".to_string(),
        initial_counter: 42,
        metadata: Some("test metadata".to_string()),
    };

    // Start with a client that has no extensions
    let client =
        AlkahestClient::<NoExtension>::new(test_context.alice.clone(), &rpc_url, None).await?;

    // Add custom tracker extension with custom config
    let client_with_tracker = client
        .with_extension::<CustomTrackerExtension, CustomTrackerConfig>(Some(custom_config.clone()))
        .await?;

    // Test retrieving the stored config
    let retrieved_config =
        client_with_tracker.get_extension_config::<CustomTrackerExtension, CustomTrackerConfig>();

    assert!(
        retrieved_config.is_some(),
        "Config should be stored and retrievable"
    );

    let config = retrieved_config.unwrap();
    assert_eq!(config.name, "config_test_tracker");
    assert_eq!(config.initial_counter, 42);
    assert_eq!(config.metadata, Some("test metadata".to_string()));

    // Test that has_extension_config works
    assert!(client_with_tracker.has_extension_config::<CustomTrackerExtension>());

    // Test that wrong type returns None
    let wrong_config =
        client_with_tracker.get_extension_config::<CustomTrackerExtension, Erc20Addresses>();
    assert!(
        wrong_config.is_none(),
        "Wrong config type should return None"
    );

    Ok(())
}

/// Test using ERC20 extension with custom addresses (original test)
#[tokio::test]
#[serial]
async fn test_client_with_extension() -> Result<()> {
    let test_context = setup_test_environment().await?;

    // Get the RPC URL from the anvil instance
    let rpc_url = test_context.anvil.ws_endpoint();

    // Create custom ERC20 addresses
    let custom_erc20_addresses = Erc20Addresses {
        eas: address!("0x1234567890123456789012345678901234567890"),
        payment_obligation: address!("0x2345678901234567890123456789012345678901"),
        escrow_obligation: address!("0x3456789012345678901234567890123456789012"),
        barter_utils: address!("0x4567890123456789012345678901234567890123"),
    };

    // Start with a client that has no extensions
    let client =
        AlkahestClient::<NoExtension>::new(test_context.alice.clone(), &rpc_url, None).await?;

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

    // Test retrieving the stored ERC20 config
    let retrieved_config = client_with_erc20.get_extension_config::<Erc20Module, Erc20Addresses>();

    assert!(
        retrieved_config.is_some(),
        "ERC20 config should be stored and retrievable"
    );

    let config = retrieved_config.unwrap();
    assert_eq!(config.eas, custom_erc20_addresses.eas);
    assert_eq!(
        config.payment_obligation,
        custom_erc20_addresses.payment_obligation
    );
    assert_eq!(
        config.escrow_obligation,
        custom_erc20_addresses.escrow_obligation
    );
    assert_eq!(config.barter_utils, custom_erc20_addresses.barter_utils);

    // Test that has_extension_config works for ERC20
    assert!(client_with_erc20.has_extension_config::<Erc20Module>());

    Ok(())
}

/// Test config retrieval when no config is provided
#[tokio::test]
#[serial]
async fn test_no_config_provided() -> Result<()> {
    let test_context = setup_test_environment().await?;

    // Get the RPC URL from the anvil instance
    let rpc_url = test_context.anvil.ws_endpoint();

    // Start with a client that has no extensions
    let client =
        AlkahestClient::<NoExtension>::new(test_context.alice.clone(), &rpc_url, None).await?;

    // Add custom tracker extension WITHOUT config
    let client_with_tracker = client
        .with_extension::<CustomTrackerExtension, CustomTrackerConfig>(None)
        .await?;

    // Test that no config is stored when None is provided
    let retrieved_config =
        client_with_tracker.get_extension_config::<CustomTrackerExtension, CustomTrackerConfig>();

    assert!(
        retrieved_config.is_none(),
        "No config should be stored when None is provided"
    );

    // Test that has_extension_config returns false
    assert!(!client_with_tracker.has_extension_config::<CustomTrackerExtension>());

    // But the extension should still work with default values
    let tracker_client = client_with_tracker
        .extensions
        .get_client::<CustomTrackerClient>();
    assert_eq!(tracker_client.name, "default_tracker");
    assert_eq!(tracker_client.counter, 0);
    assert_eq!(tracker_client.metadata, None);

    Ok(())
}

/// Test using with_initialized_extension method (original test)
#[tokio::test]
#[serial]
async fn test_client_with_initialized_extension() -> Result<()> {
    let test_context = setup_test_environment().await?;

    // Get the RPC URL from the anvil instance
    let rpc_url = test_context.anvil.ws_endpoint();

    // Create client with no extensions
    let client =
        AlkahestClient::<NoExtension>::new(test_context.alice.clone(), &rpc_url, None).await?;

    // Initialize an extension separately
    let erc20_extension = Erc20Module::init(test_context.alice.clone(), &rpc_url, None).await?;

    // Add the pre-initialized extension
    let client_with_erc20 = client.with_initialized_extension(erc20_extension);

    // Verify the extension was added
    assert!(client_with_erc20.extensions.has_client::<Erc20Client>());

    // Test accessing the client
    let _erc20_client = client_with_erc20.erc20();

    Ok(())
}
