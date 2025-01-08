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
            attestation: AttestationClient,
        })
    }
}
