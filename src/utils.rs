use alloy::{
    network::EthereumWallet,
    providers::{ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
};

use crate::types::{PublicProvider, WalletProvider};

pub async fn get_wallet_provider(
    private_key: impl ToString,
    rpc_url: impl ToString,
) -> eyre::Result<WalletProvider> {
    let signer: PrivateKeySigner = private_key.to_string().parse()?;
    let wallet = EthereumWallet::from(signer);
    let ws = WsConnect::new(rpc_url.to_string());

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_ws(ws)
        .await?;

    Ok(provider)
}

pub async fn get_public_provider(rpc_url: impl ToString) -> eyre::Result<PublicProvider> {
    let ws = WsConnect::new(rpc_url.to_string());

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_ws(ws)
        .await?;

    Ok(provider)
}
