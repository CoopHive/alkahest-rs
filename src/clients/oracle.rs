use alloy::{primitives::Address, signers::local::PrivateKeySigner};

use crate::{
    addresses::FILECOIN_CALIBRATION_ADDRESSES,
    types::{PublicProvider, WalletProvider},
    utils,
};

#[derive(Debug, Clone)]
pub struct OracleAddresses {
    pub trusted_oracle_arbiter: Address,
}

#[derive(Clone)]
pub struct OracleClient {
    _signer: PrivateKeySigner,
    public_provider: PublicProvider,
    wallet_provider: WalletProvider,

    pub addresses: OracleAddresses,
}

impl Default for OracleAddresses {
    fn default() -> Self {
        OracleAddresses {
            trusted_oracle_arbiter: FILECOIN_CALIBRATION_ADDRESSES
                .arbiters_addresses
                .unwrap()
                .trusted_oracle_arbiter,
        }
    }
}

impl OracleClient {
    pub async fn new(
        signer: PrivateKeySigner,
        rpc_url: impl ToString + Clone,
        addresses: Option<OracleAddresses>,
    ) -> eyre::Result<Self> {
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;
        let wallet_provider = utils::get_wallet_provider(signer.clone(), rpc_url.clone()).await?;

        Ok(OracleClient {
            _signer: signer,
            public_provider: public_provider.clone(),
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }
}
