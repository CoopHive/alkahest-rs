use alloy::primitives::{address, keccak256, Address, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::{Signature, Signer};
use alloy::sol_types::SolValue;

use crate::contracts::ERC20Permit;
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
    signer: PrivateKeySigner,
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
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<Erc20Addresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider = utils::get_wallet_provider(private_key.clone(), rpc_url.clone())?;
        let public_provider = utils::get_public_provider(rpc_url)?;

        Ok(Erc20Client {
            signer: private_key.to_string().parse()?,
            wallet_provider,
            public_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    async fn get_permit_signature(
        &self,
        token: Address,
        spender: Address,
        value: U256,
        deadline: U256,
    ) -> eyre::Result<Signature> {
        let token_contract = ERC20Permit::new(token, &self.wallet_provider);

        let permit_type_hash = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
        );
        let owner = self.signer.address();

        // let nonce = token_contract.nonces(owner).call().await?._0;
        // let domain_separator = token_contract.DOMAIN_SEPARATOR().call().await?._0;
        let (nonce, domain_separator) = tokio::try_join!(
            async { Ok::<_, eyre::Error>(token_contract.nonces(owner).call().await?._0) },
            async { Ok(token_contract.DOMAIN_SEPARATOR().call().await?._0) }
        )?;

        let struct_hash = (permit_type_hash, owner, spender, value, nonce, deadline).abi_encode();

        let digest = keccak256((&[0x19, 0x01], domain_separator, struct_hash).abi_encode_packed());
        let signature = self.signer.sign_message(digest.as_ref()).await?;

        Ok(signature)
    }
}
