//! Example demonstrating the modular extension system in Alkahest SDK
//!
//! This example shows various ways to configure and use extensions:
//! - Using individual modules
//! - Combining multiple modules
//! - Custom configurations
//! - Builder patterns
//! - Creating custom extensions

use alkahest_rs::{
    AlkahestClient, DefaultExtensionConfig,
    addresses::BASE_SEPOLIA_ADDRESSES,
    builders::{AlkahestClientBuilder, presets},
    clients::{
        attestation::{AttestationAddresses, AttestationModule},
        erc20::{Erc20Addresses, Erc20Module},
        erc721::{Erc721Addresses, Erc721Module},
    },
    extensions::{
        AlkahestExtension, BaseExtensions, HasErc20, HasErc721, JoinConfig, JoinExtension,
        NoExtension,
    },
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

    // Example 1: Minimal client with no extensions
    println!("1️⃣ Minimal client (no extensions):");
    let minimal_client =
        AlkahestClient::<NoExtension>::new(private_key.clone(), rpc_url, None).await?;
    println!(
        "   ✅ Created minimal client with address: {}",
        minimal_client.address
    );
    println!();

    // Example 2: Client with single module
    println!("2️⃣ Single module (ERC20 only):");
    let erc20_config = Some(BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone());
    let erc20_client =
        AlkahestClient::<Erc20Module>::new(private_key.clone(), rpc_url, erc20_config).await?;
    println!("   ✅ Created ERC20-only client");
    println!("   EAS address: {}", erc20_client.erc20().addresses.eas);
    println!();

    // Example 3: Combining two modules with JoinExtension
    println!("3️⃣ Combining modules (ERC20 + ERC721):");
    let join_config = JoinConfig {
        left_config: Some(BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone()),
        right_config: Some(BASE_SEPOLIA_ADDRESSES.erc721_addresses.clone()),
    };
    let combined_client = AlkahestClient::<JoinExtension<Erc20Module, Erc721Module>>::new(
        private_key.clone(),
        rpc_url,
        Some(join_config),
    )
    .await?;
    println!("   ✅ Created client with ERC20 and ERC721 modules");
    println!("   ERC20 EAS: {}", combined_client.erc20().addresses.eas);
    println!(
        "   ERC721 Utils: {}",
        combined_client.erc721().addresses.barter_utils
    );
    println!();

    // Example 4: Using all base extensions (traditional approach)
    println!("4️⃣ All base extensions:");
    let full_client = AlkahestClient::<BaseExtensions>::new(
        private_key.clone(),
        rpc_url,
        Some(BASE_SEPOLIA_ADDRESSES),
    )
    .await?;
    println!("   ✅ Created client with all base extensions");
    println!(
        "   Available modules: ERC20, ERC721, ERC1155, TokenBundle, Attestation, StringObligation, Arbiters, Oracle"
    );
    println!();

    // Example 5: Using the builder pattern
    println!("5️⃣ Using AlkahestClientBuilder:");

    let builder = AlkahestClientBuilder::new(private_key.clone(), rpc_url);

    // Build ERC20-only client
    let builder_erc20 = AlkahestClientBuilder::new(private_key.clone(), rpc_url)
        .build_erc20_only(Some(BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone()))
        .await?;
    println!("   ✅ Built ERC20-only client");

    // Build client with all token modules
    let builder_tokens = AlkahestClientBuilder::new(private_key.clone(), rpc_url)
        .build_all_tokens(
            Some(BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone()),
            Some(BASE_SEPOLIA_ADDRESSES.erc721_addresses.clone()),
            Some(BASE_SEPOLIA_ADDRESSES.erc1155_addresses.clone()),
            Some(BASE_SEPOLIA_ADDRESSES.token_bundle_addresses.clone()),
        )
        .await?;
    println!("   ✅ Built client with all token modules");
    println!();

    // Example 6: Using preset configurations
    println!("6️⃣ Using preset configurations:");
    let preset_client = presets::base_sepolia_client(private_key.clone(), rpc_url).await?;
    println!("   ✅ Created Base Sepolia client from preset");

    let preset_erc20 = presets::base_sepolia_erc20_client(private_key.clone(), rpc_url).await?;
    println!("   ✅ Created Base Sepolia ERC20-only client from preset");
    println!();

    // Example 7: Custom configuration
    println!("7️⃣ Custom configuration:");
    let mut custom_erc20_addresses = BASE_SEPOLIA_ADDRESSES.erc20_addresses.clone();
    custom_erc20_addresses.eas = "0x1234567890123456789012345678901234567890".parse()?;

    let custom_client = AlkahestClient::<Erc20Module>::new(
        private_key.clone(),
        rpc_url,
        Some(custom_erc20_addresses.clone()),
    )
    .await?;
    println!("   ✅ Created client with custom ERC20 addresses");
    println!(
        "   Custom EAS address: {}",
        custom_client.erc20().addresses.eas
    );
    println!();

    // Example 8: Implementing a custom extension
    println!("8️⃣ Custom extension implementation:");

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

    let custom_ext_client =
        AlkahestClient::<MyCustomExtension>::new(private_key.clone(), rpc_url, Some(custom_config))
            .await?;

    println!("   ✅ Created client with custom extension");
    println!("   Custom data: {}", custom_ext_client.extensions.my_data);
    println!("   ERC20 EAS: {}", custom_ext_client.erc20().addresses.eas);
    println!();

    // Example 9: Dynamic module selection based on runtime conditions
    println!("9️⃣ Dynamic module selection:");

    let use_attestation = true; // This could be from config, env var, etc.

    if use_attestation {
        let attestation_client = AlkahestClient::<AttestationModule>::new(
            private_key.clone(),
            rpc_url,
            Some(BASE_SEPOLIA_ADDRESSES.attestation_addresses.clone()),
        )
        .await?;
        println!("   ✅ Created client with Attestation module (based on runtime condition)");
        println!(
            "   Attestation EAS: {}",
            attestation_client.extensions.addresses.eas
        );
    } else {
        let minimal =
            AlkahestClient::<NoExtension>::new(private_key.clone(), rpc_url, None).await?;
        println!("   ✅ Created minimal client (attestation not needed)");
    }
    println!();

    println!("✅ All examples completed successfully!");
    println!("\n📝 Key takeaways:");
    println!("   - Extensions are modular and can be used individually");
    println!("   - Each extension has its own configuration type");
    println!("   - Extensions can be combined using JoinExtension");
    println!("   - The builder pattern provides convenient presets");
    println!("   - Custom extensions can be easily implemented");
    println!("   - Module selection can be dynamic based on runtime needs");

    Ok(())
}
