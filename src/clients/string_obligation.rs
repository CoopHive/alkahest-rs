use alloy::{
    primitives::{Address, Bytes, FixedBytes},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol_types::SolValue as _,
};
use serde::de::DeserializeOwned;

use crate::{
    addresses::BASE_SEPOLIA_ADDRESSES,
    contracts,
    types::{DecodedAttestation, WalletProvider},
};

#[derive(Debug, Clone)]
pub struct StringObligationAddresses {
    pub eas: Address,
    pub obligation: Address,
}

#[derive(Clone)]
pub struct StringObligationClient {
    _signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: StringObligationAddresses,
}

impl Default for StringObligationAddresses {
    fn default() -> Self {
        BASE_SEPOLIA_ADDRESSES.string_obligation_addresses.unwrap()
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
        signer: PrivateKeySigner,
        rpc_url: impl ToString + Clone,
        addresses: Option<StringObligationAddresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = crate::utils::get_wallet_provider(signer.clone(), rpc_url).await?;

        Ok(StringObligationClient {
            _signer: signer,
            wallet_provider,
            addresses: addresses.unwrap_or_default(),
        })
    }

    pub async fn get_statement(
        &self,
        uid: FixedBytes<32>,
    ) -> eyre::Result<DecodedAttestation<contracts::StringObligation::StatementData>> {
        let eas_contract = contracts::IEAS::new(self.addresses.eas, &self.wallet_provider);

        let attestation = eas_contract.getAttestation(uid).call().await?;
        let statement_data =
            contracts::StringObligation::StatementData::abi_decode(&attestation.data)?;

        Ok(DecodedAttestation {
            attestation,
            data: statement_data,
        })
    }

    pub fn decode(
        statement_data: &Bytes,
    ) -> eyre::Result<contracts::StringObligation::StatementData> {
        let statementdata =
            contracts::StringObligation::StatementData::abi_decode(statement_data.as_ref())?;
        Ok(statementdata)
    }

    pub fn decode_json<T: DeserializeOwned>(statement_data: &Bytes) -> eyre::Result<T> {
        let decoded: T = serde_json::from_str(&Self::decode(statement_data)?.item)?;
        Ok(decoded)
    }

    pub fn encode(statement_data: &contracts::StringObligation::StatementData) -> Bytes {
        return contracts::StringObligation::StatementData::abi_encode(&statement_data).into();
    }

    pub fn encode_json<T: serde::Serialize>(statement_data: T) -> eyre::Result<Bytes> {
        let encoded = Self::encode(&contracts::StringObligation::StatementData {
            item: serde_json::to_string(&statement_data)?,
        });
        Ok(encoded)
    }

    pub async fn make_statement(
        &self,
        statement_data: contracts::StringObligation::StatementData,
        ref_uid: Option<FixedBytes<32>>,
    ) -> eyre::Result<TransactionReceipt> {
        let contract =
            contracts::StringObligation::new(self.addresses.obligation, &self.wallet_provider);

        let receipt = contract
            .makeStatement(
                statement_data,
                ref_uid.unwrap_or(FixedBytes::<32>::default()),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn make_statement_json<T: serde::Serialize>(
        &self,
        statement_data: T,
        ref_uid: Option<FixedBytes<32>>,
    ) -> eyre::Result<TransactionReceipt> {
        let contract =
            contracts::StringObligation::new(self.addresses.obligation, &self.wallet_provider);

        let statement_data = contracts::StringObligation::StatementData {
            item: serde_json::to_string(&statement_data)?,
        };
        let receipt = contract
            .makeStatement(
                statement_data,
                ref_uid.unwrap_or(FixedBytes::<32>::default()),
            )
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }
}
