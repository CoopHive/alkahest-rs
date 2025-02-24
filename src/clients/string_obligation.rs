use alloy::{
    primitives::{address, Address},
    signers::local::PrivateKeySigner,
};

use crate::types::WalletProvider;

#[derive(Debug, Clone)]
pub struct StringObligationAddresses {
    pub eas: Address,
    pub obligation: Address,
}

#[derive(Clone)]
pub struct StringObligationClient {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: StringObligationAddresses,
}

impl Default for StringObligationAddresses {
    fn default() -> Self {
        Self {
            eas: address!("0x4200000000000000000000000000000000000021"),
            obligation: address!("0xb4692f27f3Ef6968394F12eb5843e7C494a0Ed72"),
        }
    }
}

impl StringObligationClient {
    /// Creates a new StringObligationClient instance.
    ///
    /// # Arguments
    /// * `private_key` - The private key for signing transactions
    /// * `rpc_url` - The RPC endpoint URL
    /// * `addresses` - Optional custom contract addresses, uses defaults if None
    ///
    /// # Returns
    /// * `Result<Self>` - The initialized client instance with all sub-clients configured
    pub async fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<StringObligationAddresses>,
    ) -> eyre::Result<Self> {
        let signer: PrivateKeySigner = private_key.to_string().parse()?;
        let wallet_provider = crate::utils::get_wallet_provider(private_key, rpc_url).await?;

        Ok(StringObligationClient {
            signer,
            wallet_provider,
            addresses: addresses.unwrap_or_default(),
        })
    }
}
