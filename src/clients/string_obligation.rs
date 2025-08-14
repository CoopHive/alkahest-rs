use crate::{
    DefaultExtensionConfig,
    addresses::BASE_SEPOLIA_ADDRESSES,
    contracts,
    extensions::AlkahestExtension,
    types::{DecodedAttestation, WalletProvider},
};
use alloy::providers::Provider;
use alloy::{
    primitives::{Address, Bytes, FixedBytes},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol_types::SolValue as _,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::any::Any;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringObligationAddresses {
    pub eas: Address,
    pub obligation: Address,
}

#[derive(Clone)]
pub struct StringObligationModule {
    _signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: StringObligationAddresses,
}

impl Default for StringObligationAddresses {
    fn default() -> Self {
        BASE_SEPOLIA_ADDRESSES.string_obligation_addresses
    }
}

impl StringObligationModule {
    /// Creates a new StringObligationModule instance.
    ///
    /// # Arguments
    /// * `private_key` - The private key for signing transactions
    /// * `rpc_url` - The RPC endpoint URL
    /// * `addresses` - Optional custom contract addresses, uses defaults if None
    ///
    /// # Returns
    /// * `Result<Self>` - The initialized client instance with all sub-clients configured
    pub async fn new(
        signer: PrivateKeySigner,
        rpc_url: impl ToString + Clone,
        addresses: Option<StringObligationAddresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = crate::utils::get_wallet_provider(signer.clone(), rpc_url).await?;

        Ok(StringObligationModule {
            _signer: signer,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub async fn get_obligation(
        &self,
        uid: FixedBytes<32>,
    ) -> eyre::Result<DecodedAttestation<contracts::StringObligation::ObligationData>> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);

        let attestation = eas_contract.getAttestation(uid).call().await?;
        let obligation_data =
            contracts::StringObligation::ObligationData::abi_decode(&attestation.data)?;

        Ok(DecodedAttestation {
            attestation,
            data: obligation_data,
        })
    }

    pub fn decode(
        obligation_data: &Bytes,
    ) -> eyre::Result<contracts::StringObligation::ObligationData> {
        let obligationdata =
            contracts::StringObligation::ObligationData::abi_decode(obligation_data.as_ref())?;
        Ok(obligationdata)
    }

    pub fn decode_json<T: DeserializeOwned>(obligation_data: &Bytes) -> eyre::Result<T> {
        let decoded: T = serde_json::from_str(&Self::decode(obligation_data)?.item)?;
        Ok(decoded)
    }

    pub fn encode(obligation_data: &contracts::StringObligation::ObligationData) -> Bytes {
        return contracts::StringObligation::ObligationData::abi_encode(&obligation_data).into();
    }

    pub fn encode_json<T: serde::Serialize>(obligation_data: T) -> eyre::Result<Bytes> {
        let encoded = Self::encode(&contracts::StringObligation::ObligationData {
            item: serde_json::to_string(&obligation_data)?,
        });
        Ok(encoded)
    }

    pub async fn do_obligation(
        &self,
        item: String,
        ref_uid: Option<FixedBytes<32>>,
    ) -> eyre::Result<TransactionReceipt> {
        let contract =
            contracts::StringObligation::new(self.addresses.obligation, &self.wallet_provider);

        let obligation_data = contracts::StringObligation::ObligationData { item };

        let address = self._signer.address();
        let nonce = self.wallet_provider.get_transaction_count(address).await?;

        let receipt = contract
            .doObligation(
                obligation_data,
                ref_uid.unwrap_or(FixedBytes::<32>::default()),
            )
            .nonce(nonce)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn do_obligation_json<T: serde::Serialize>(
        &self,
        obligation_data: T,
        ref_uid: Option<FixedBytes<32>>,
    ) -> eyre::Result<TransactionReceipt> {
        let contract =
            contracts::StringObligation::new(self.addresses.obligation, &self.wallet_provider);

        let obligation_data = contracts::StringObligation::ObligationData {
            item: serde_json::to_string(&obligation_data)?,
        };
        let receipt = contract
            .doObligation(
                obligation_data,
                ref_uid.unwrap_or(FixedBytes::<32>::default()),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}

impl AlkahestExtension for StringObligationModule {
    async fn init(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        config: Option<DefaultExtensionConfig>,
    ) -> eyre::Result<Self> {
        Self::new(
            private_key,
            rpc_url,
            config.map(|c| c.string_obligation_addresses),
        )
        .await
    }

    async fn init_with_config<A: Clone + Send + Sync + 'static>(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        config: Option<A>,
    ) -> eyre::Result<Self> {
        // Try to downcast to StringObligationAddresses first
        let string_obligation_addresses = if let Some(addr) = config {
            let addr_any: &dyn Any = &addr;
            if let Some(string_addr) = addr_any.downcast_ref::<StringObligationAddresses>() {
                Some(string_addr.clone())
            } else {
                None
            }
        } else {
            None
        };

        Self::new(private_key, rpc_url, string_obligation_addresses).await
    }
}
