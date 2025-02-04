use alloy::{
    primitives::{Address, FixedBytes, Log},
    providers::Provider,
    rpc::types::{Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
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
    pub wallet_provider: WalletProvider,
    pub public_provider: PublicProvider,

    pub address: Address,
    pub erc20: Erc20Client,
    pub erc721: Erc721Client,
    pub erc1155: Erc1155Client,
    pub token_bundle: TokenBundleClient,
    pub attestation: AttestationClient,
}

impl AlkahestClient {
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
            erc20: make_client!(Erc20Client, erc20_addresses).await?,
            erc721: make_client!(Erc721Client, erc721_addresses).await?,
            erc1155: make_client!(Erc1155Client, erc1155_addresses).await?,
            token_bundle: make_client!(TokenBundleClient, token_bundle_addresses).await?,
            attestation: make_client!(AttestationClient, attestation_addresses).await?,
        })
    }

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
