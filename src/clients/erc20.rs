use alloy::primitives::{address, Address};

use crate::{
    types::{PublicProvider, WalletProvider},
    utils,
};

pub struct Erc20Addresses {
    barter_utils: Address,
    escrow_obligation: Address,
    payment_obligation: Address,
}

pub struct Erc20Client {
    wallet_provider: WalletProvider,
    public_provider: PublicProvider,

    addresses: Erc20Addresses,
}

impl Default for Erc20Addresses {
    fn default() -> Self {
        Self {
            barter_utils: address!("3A40F65D2589a43Dc057bf820D8626F87D95307c"),
            escrow_obligation: address!("248cd93922eBDf962c9ea10286E6566C75081948"),
            payment_obligation: address!("702fab66515b3313dFd41E7CE70C2aF0033E2356"),
        }
    }
}

impl Erc20Client {
    pub fn new(
        private_key: impl ToString,
        rpc_url: impl ToString + Clone,
        addresses: Option<Erc20Addresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key, rpc_url.clone())?;
        let public_provider = utils::get_public_provider(rpc_url)?;

        Ok(Erc20Client {
            wallet_provider,
            public_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }
}
