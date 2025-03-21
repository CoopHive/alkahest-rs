use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::PrimitiveSignature,
    providers::{ProviderBuilder, WsConnect, ext::AnvilApi},
    signers::{Signature, Signer, local::PrivateKeySigner},
};

use crate::{
    AlkahestClient,
    types::{PublicProvider, WalletProvider},
};

pub async fn get_wallet_provider<T: TxSigner<PrimitiveSignature> + Sync + Send + 'static>(
    private_key: T,
    rpc_url: impl ToString,
) -> eyre::Result<WalletProvider> {
    let wallet = EthereumWallet::from(private_key);
    let ws = WsConnect::new(rpc_url.to_string());

    let provider = ProviderBuilder::new().wallet(wallet).on_ws(ws).await?;

    Ok(provider)
}

pub async fn get_public_provider(rpc_url: impl ToString) -> eyre::Result<PublicProvider> {
    let ws = WsConnect::new(rpc_url.to_string());

    let provider = ProviderBuilder::new().on_ws(ws).await?;

    Ok(provider)
}
