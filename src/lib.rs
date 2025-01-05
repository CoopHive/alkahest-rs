use clients::{
    attestation::AttestationClient, erc1155::Erc1155Client, erc20::Erc20Client,
    erc721::Erc721Client, token_bundle::TokenBundleClient,
};
use types::{PublicProvider, WalletProvider};

pub mod clients;
pub mod config;
pub mod contracts;
pub mod types;
pub mod utils;

pub struct AlkahestClient {
    wallet_provider: WalletProvider,
    public_provider: PublicProvider,

    erc20: Erc20Client,
    erc721: Erc721Client,
    erc1155: Erc1155Client,
    token_bundle: TokenBundleClient,
    attestation: AttestationClient,
}

impl AlkahestClient {
    pub fn new(private_key: impl ToString, rpc_url: impl ToString + Clone) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key, rpc_url.clone())?;
        let public_provider = utils::get_public_provider(rpc_url)?;

        Ok(AlkahestClient {
            wallet_provider,
            public_provider,

            erc20: Erc20Client,
            erc721: Erc721Client,
            erc1155: Erc1155Client,
            token_bundle: TokenBundleClient,
            attestation: AttestationClient,
        })
    }
}
