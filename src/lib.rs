use alloy::{
    primitives::{Address, FixedBytes, Log},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use clients::{
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

#[derive(Debug, Clone)]
pub struct AddressConfig {
    pub erc20_addresses: Option<Erc20Addresses>,
    pub erc721_addresses: Option<Erc721Addresses>,
    pub erc1155_addresses: Option<Erc1155Addresses>,
    pub token_bundle_addresses: Option<TokenBundleAddresses>,
    pub attestation_addresses: Option<AttestationAddresses>,
}

#[derive(Clone)]
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
        addresses: Option<AddressConfig>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key.clone(), rpc_url.clone())?;
        let public_provider = utils::get_public_provider(rpc_url.clone())?;

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

            erc20: make_client!(Erc20Client, erc20_addresses)?,
            erc721: make_client!(Erc721Client, erc721_addresses)?,
            erc1155: make_client!(Erc1155Client, erc1155_addresses)?,
            token_bundle: make_client!(TokenBundleClient, token_bundle_addresses)?,
            attestation: make_client!(AttestationClient, attestation_addresses)?,
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
