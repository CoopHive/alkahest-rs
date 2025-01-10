use alloy::{
    primitives::{Address, FixedBytes, Log, B256, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol,
    sol_types::SolEvent,
};
use clients::{
    attestation::AttestationClient, erc1155::Erc1155Client, erc20::Erc20Client,
    erc721::Erc721Client, token_bundle::TokenBundleClient,
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

pub struct AlkahestClient {
    wallet_provider: WalletProvider,
    public_provider: PublicProvider,

    pub erc20: Erc20Client,
    pub erc721: Erc721Client,
    pub erc1155: Erc1155Client,
    pub token_bundle: TokenBundleClient,
    pub attestation: AttestationClient,
}

impl AlkahestClient {
    pub fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key.clone(), rpc_url.clone())?;
        let public_provider = utils::get_public_provider(rpc_url.clone())?;

        Ok(AlkahestClient {
            wallet_provider: wallet_provider.clone(),
            public_provider: public_provider.clone(),

            erc20: Erc20Client::new(private_key.clone(), rpc_url.clone(), None)?,
            erc721: Erc721Client::new(private_key.clone(), rpc_url.clone(), None)?,
            erc1155: Erc1155Client::new(private_key.clone(), rpc_url.clone(), None)?,
            token_bundle: TokenBundleClient::new(private_key.clone(), rpc_url.clone(), None)?,
            attestation: AttestationClient::new(private_key.clone(), rpc_url.clone(), None)?,
        })
    }

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

        while let Some(log) = stream.next().await {
            let log = log.log_decode::<EscrowClaimed>()?;
            return Ok(log.inner);
        }

        Err(eyre::eyre!("No EscrowClaimed event found"))
    }
}
