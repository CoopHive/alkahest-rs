use alloy::{
    primitives::{address, Address, Bytes, FixedBytes},
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    sol_types::SolValue as _,
};
use serde::de::DeserializeOwned;

use crate::{contracts, types::WalletProvider};

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

    pub fn decode(
        statement_data: Bytes,
    ) -> eyre::Result<contracts::StringObligation::StatementData> {
        let statementdata =
            contracts::StringObligation::StatementData::abi_decode(statement_data.as_ref(), true)?;
        Ok(statementdata)
    }

    pub fn decode_json<T: DeserializeOwned>(statement_data: Bytes) -> eyre::Result<T> {
        let decoded: T = serde_json::from_str(&Self::decode(statement_data)?.item)?;
        Ok(decoded)
    }

    pub fn encode(statement_data: contracts::StringObligation::StatementData) -> Bytes {
        return contracts::StringObligation::StatementData::abi_encode(&statement_data).into();
    }

    pub fn encode_json<T: serde::Serialize>(statement_data: T) -> eyre::Result<Bytes> {
        let encoded = Self::encode(contracts::StringObligation::StatementData {
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
