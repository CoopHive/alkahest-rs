use alloy::{
    primitives::{Address, FixedBytes, Log},
    providers::Provider,
    rpc::types::{Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use extensions::{AlkahestExtension, BaseExtensions, ExtensionAddresses};
use futures_util::StreamExt;
use sol_types::EscrowClaimed;
use types::{PublicProvider, WalletProvider};

/// Type alias for the default AlkahestClient with BaseExtensions
pub type DefaultAlkahestClient = AlkahestClient<BaseExtensions>;

pub mod addresses;
pub mod clients;
pub mod contracts;
pub mod extensions;
pub mod fixtures;
pub mod sol_types;
pub mod types;
pub mod utils;

#[derive(Clone)]
pub struct AlkahestClient<Extensions: AlkahestExtension = BaseExtensions> {
    pub wallet_provider: WalletProvider,
    pub public_provider: PublicProvider,
    pub address: Address,
    pub extensions: Extensions,
}

impl<Extensions: AlkahestExtension> AlkahestClient<Extensions> {
    pub async fn new(
        private_key: PrivateKeySigner,
        rpc_url: impl ToString + Clone + Send,
        addresses: Option<ExtensionAddresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider =
            utils::get_wallet_provider(private_key.clone(), rpc_url.clone()).await?;
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;

        let extensions = Extensions::init(private_key.clone(), rpc_url, addresses).await?;

        Ok(AlkahestClient {
            wallet_provider,
            public_provider,
            address: private_key.address(),
            extensions,
        })
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
