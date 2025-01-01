use clients::{
    attestation::AttestationClient, erc1155::Erc1155Client, erc20::Erc20Client,
    erc721::Erc721Client, token_bundle::TokenBundleClient,
};
use types::WalletProvider;

pub mod clients;
pub mod config;
pub mod types;
pub mod utils;

pub struct AlkahestClient {
    provider: WalletProvider,

    erc20: Erc20Client,
    erc721: Erc721Client,
    erc1155: Erc1155Client,
    token_bundle: TokenBundleClient,
    attestation: AttestationClient,
}

impl AlkahestClient {
    pub fn new(private_key: impl ToString, rpc_url: impl ToString) -> eyre::Result<Self> {
        let signer: PrivateKeySigner = private_key.parse()?;
    }
}
