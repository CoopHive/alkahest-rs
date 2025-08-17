//! Example demonstrating the modular extension system in Alkahest SDK
//!
//! This example shows various ways to configure and use extensions:
//! - Starting with no extensions and adding them via chaining
//! - Using specific module configurations
//! - Creating custom extensions
//! - Using default configurations

use alkahest_rs::{
    AlkahestClient,
    addresses::BASE_SEPOLIA_ADDRESSES,
    clients::{
        attestation::AttestationModule,
        erc20::{Erc20Addresses, Erc20Module},
        erc721::Erc721Module,
        erc1155::Erc1155Module,
        token_bundle::TokenBundleModule,
    },
    extensions::{AlkahestExtension, HasErc20, HasErc721},
};
use alloy::signers::local::PrivateKeySigner;
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup
    let private_key: PrivateKeySigner =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".parse()?;
    let rpc_url = "https://base-sepolia-rpc.publicnode.com";

    println!("🧩 Modular Extension System Examples\n");

    // Example 1: Start with no extensions and chain them
    println!("1️⃣ Building client by chaining extensions:");
    let client = AlkahestClient::new(private_key.clone(), rpc_url).await?;
    println!(
        "   ✅ Created minimal client with address: {}",
        client.address
    );

    // Add ERC20 module with custom config
    let erc20_config = BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone();
    let client_with_erc20 = client
        .with_extension::<Erc20Module>(Some(erc20_config))
        .await?;
    println!("   ✅ Added ERC20 module");
    println!(
        "   EAS address: {}",
        client_with_erc20.erc20().addresses.eas
    );

    // Add ERC721 module
    let erc721_config = BASE_SEPOLIA_ADDRESSES.erc721_addresses.clone();
    let client_with_both = client_with_erc20
        .with_extension::<Erc721Module>(Some(erc721_config))
        .await?;
    println!("   ✅ Added ERC721 module");
    println!(
        "   ERC721 Utils: {}",
        client_with_both.erc721().addresses.barter_utils
    );
    println!();

    // Example 2: Using default configurations
    println!("2️⃣ Using default configurations:");
    let client_defaults = AlkahestClient::new(private_key.clone(), rpc_url)
        .await?
        .with_extension_default::<Erc20Module>()
        .await?
        .with_extension_default::<Erc721Module>()
        .await?;
    println!("   ✅ Created client with ERC20 and ERC721 using defaults");
    println!();

    // Example 3: Start with all base extensions
    println!("3️⃣ Starting with all base extensions:");
    let full_client = AlkahestClient::with_base_extensions(
        private_key.clone(),
        rpc_url,
        Some(BASE_SEPOLIA_ADDRESSES),
    )
    .await?;
    println!("   ✅ Created client with all base extensions");
    println!(
        "   Available: ERC20, ERC721, ERC1155, TokenBundle, Attestation, StringObligation, Arbiters, Oracle"
    );
    println!();

    // Example 4: Chain multiple extensions with mixed configurations
    println!("4️⃣ Chaining multiple extensions with mixed configs:");
    let multi_client = AlkahestClient::new(private_key.clone(), rpc_url)
        .await?
        .with_extension::<Erc20Module>(Some(BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone()))
        .await?
        .with_extension_default::<Erc721Module>()
        .await?
        .with_extension::<Erc1155Module>(Some(BASE_SEPOLIA_ADDRESSES.erc1155_addresses.clone()))
        .await?
        .with_extension::<TokenBundleModule>(Some(
            BASE_SEPOLIA_ADDRESSES.token_bundle_addresses.clone(),
        ))
        .await?;
    println!("   ✅ Built client with multiple token modules via chaining");
    println!();

    // Example 5: Custom configuration
    println!("5️⃣ Custom configuration:");
    let mut custom_erc20_addresses = BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone();
    custom_erc20_addresses.eas = "0x1234567890123456789012345678901234567890".parse()?;

    let custom_client = AlkahestClient::new(private_key.clone(), rpc_url)
        .await?
        .with_extension::<Erc20Module>(Some(custom_erc20_addresses.clone()))
        .await?;
    println!("   ✅ Created client with custom ERC20 addresses");
    println!(
        "   Custom EAS address: {}",
        custom_client.erc20().addresses.eas
    );
    println!();

    // Example 6: Implementing a custom extension
    println!("6️⃣ Custom extension implementation:");

    // Define a custom extension
    #[derive(Clone)]
    struct MyCustomExtension {
        my_data: String,
        erc20: Erc20Module,
    }

    #[derive(Clone)]
    struct MyCustomConfig {
        my_data: String,
        erc20_addresses: Erc20Addresses,
    }

    impl AlkahestExtension for MyCustomExtension {
        type Config = MyCustomConfig;

        async fn init(
            private_key: PrivateKeySigner,
            rpc_url: impl ToString + Clone + Send,
            config: Option<Self::Config>,
        ) -> Result<Self> {
            let config = config.unwrap_or_else(|| MyCustomConfig {
                my_data: "default".to_string(),
                erc20_addresses: BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone(),
            });

            let erc20 =
                Erc20Module::init(private_key, rpc_url, Some(config.erc20_addresses)).await?;

            Ok(MyCustomExtension {
                my_data: config.my_data,
                erc20,
            })
        }

        // Override find_client to support finding the nested ERC20 module
        fn find_client<T: Clone + Send + Sync + 'static>(&self) -> Option<&T> {
            // First try to downcast self
            let self_any: &dyn std::any::Any = self;
            if let Some(client) = self_any.downcast_ref::<T>() {
                return Some(client);
            }
            // Then delegate to nested modules
            self.erc20.find_client::<T>()
        }
    }

    // Implement HasErc20 for our custom extension
    impl HasErc20 for MyCustomExtension {
        fn erc20(&self) -> &Erc20Module {
            &self.erc20
        }
    }

    let custom_config = MyCustomConfig {
        my_data: "Hello from custom extension!".to_string(),
        erc20_addresses: BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone(),
    };

    // Add custom extension to an existing client
    let base_client = AlkahestClient::new(private_key.clone(), rpc_url).await?;
    let custom_ext_client = base_client
        .with_extension::<MyCustomExtension>(Some(custom_config))
        .await?;

    println!("   ✅ Added custom extension to client");
    // Note: When using with_extension, the custom extension is wrapped in JoinExtension
    // To access custom fields, you'd need to implement trait methods or use find_client
    println!("   ✅ Custom extension added (contains custom data and nested ERC20)");
    println!("   ERC20 EAS: {}", custom_ext_client.erc20().addresses.eas);
    println!();

    // Example 7: Dynamic module selection based on runtime conditions
    println!("7️⃣ Dynamic module selection:");

    let use_attestation = true; // This could be from config, env var, etc.

    let mut dynamic_client = AlkahestClient::new(private_key.clone(), rpc_url).await?;

    if use_attestation {
        let client_with_attestation = dynamic_client
            .with_extension::<AttestationModule>(Some(
                BASE_SEPOLIA_ADDRESSES.attestation_addresses.clone(),
            ))
            .await?;
        println!("   ✅ Added Attestation module based on runtime condition");
        // Use find_client to access the AttestationModule within the JoinExtension
        if let Some(attestation) = client_with_attestation
            .extensions
            .find_client::<AttestationModule>()
        {
            println!("   Attestation EAS: {}", attestation.addresses.eas);
        }
    } else {
        println!("   ✅ Keeping minimal client (attestation not needed)");
    }
    println!();

    println!("✅ All examples completed successfully!");
    println!("\n📝 Key takeaways:");
    println!("   - Start with a minimal client and chain extensions as needed");
    println!("   - Use .with_extension() for specific configurations");
    println!("   - Use .with_extension_default() when the extension config implements Default");
    println!("   - Each extension has its own configuration type");
    println!("   - Custom extensions can be easily implemented and added");
    println!("   - Module selection can be dynamic based on runtime needs");
    println!("   - Use AlkahestClient::with_base_extensions() for the common case of all modules");

    Ok(())
}
