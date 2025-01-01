use crate::types::{PublicProvider, WalletProvider};
use alloy::{
    network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
};

pub fn get_wallet_provider(
    private_key: impl ToString,
    rpc_url: impl ToString,
) -> eyre::Result<WalletProvider> {
    let signer: PrivateKeySigner = private_key.to_string().parse()?;
    let wallet = EthereumWallet::from(signer);
    let rpc_url = rpc_url.to_string().parse()?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(rpc_url);

    Ok(provider)
}

pub fn get_public_provider(rpc_url: impl ToString) -> eyre::Result<PublicProvider> {
    let rpc_url = rpc_url.to_string().parse()?;

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http(rpc_url);

    Ok(provider)
}
