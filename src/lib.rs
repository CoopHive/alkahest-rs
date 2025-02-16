use alloy::{
    primitives::{Address, FixedBytes, Log},
    providers::Provider,
    rpc::types::{Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use clients::{
    arbiters::{ArbitersAddresses, ArbitersClient},
    attestation::{AttestationAddresses, AttestationClient},
    erc1155::{Erc1155Addresses, Erc1155Client},
    erc20::{Erc20Addresses, Erc20Client},
    erc721::{Erc721Addresses, Erc721Client},
    token_bundle::{TokenBundleAddresses, TokenBundleClient},
};
use futures_util::StreamExt;
use sol_types::EscrowClaimed;
use types::{PublicProvider, WalletProvider};

pub mod clients;
pub mod config;
pub mod contracts;
pub mod sol_types;
pub mod types;
pub mod utils;

/// Configuration for contract addresses used by the AlkahestClient.
/// Each field is optional and will use default addresses if not provided.
#[derive(Debug, Clone)]
pub struct AddressConfig {
    pub arbiters_addresses: Option<ArbitersAddresses>,
    pub erc20_addresses: Option<Erc20Addresses>,
    pub erc721_addresses: Option<Erc721Addresses>,
    pub erc1155_addresses: Option<Erc1155Addresses>,
    pub token_bundle_addresses: Option<TokenBundleAddresses>,
    pub attestation_addresses: Option<AttestationAddresses>,
}

/// The main client for interacting with token trading and attestation functionality.
///
/// This client provides a unified interface for:
/// - Trading ERC20, ERC721, and ERC1155 tokens
/// - Managing token bundles
/// - Creating and managing attestations
/// - Setting up escrow arrangements
/// - Handling trade fulfillment
#[derive(Clone)]
pub struct AlkahestClient {
    pub wallet_provider: WalletProvider,
    pub public_provider: PublicProvider,
    pub address: Address,

    pub arbiters: ArbitersClient,
    pub erc20: Erc20Client,
    pub erc721: Erc721Client,
    pub erc1155: Erc1155Client,
    pub token_bundle: TokenBundleClient,
    pub attestation: AttestationClient,
}

impl AlkahestClient {
    /// Creates a new AlkahestClient instance.
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
        addresses: Option<AddressConfig>,
    ) -> eyre::Result<Self> {
        let wallet_provider =
            utils::get_wallet_provider(private_key.clone(), rpc_url.clone()).await?;
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;
        let signer: PrivateKeySigner = private_key.to_string().parse()?;

        macro_rules! make_client {
            ($client:ident, $addresses:ident) => {
                $client::new(
                    private_key.clone(),
                    rpc_url.clone(),
                    addresses.clone().and_then(|a| a.$addresses),
                )
            };
        }

        Ok(AlkahestClient {
            wallet_provider: wallet_provider.clone(),
            public_provider: public_provider.clone(),
            address: signer.address(),
            arbiters: make_client!(ArbitersClient, arbiters_addresses).await?,
            erc20: make_client!(Erc20Client, erc20_addresses).await?,
            erc721: make_client!(Erc721Client, erc721_addresses).await?,
            erc1155: make_client!(Erc1155Client, erc1155_addresses).await?,
            token_bundle: make_client!(TokenBundleClient, token_bundle_addresses).await?,
            attestation: make_client!(AttestationClient, attestation_addresses).await?,
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
