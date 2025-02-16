use alloy::{
    primitives::{address, Address, Bytes},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolValue as _,
};

use crate::{types::WalletProvider, utils};

#[derive(Debug, Clone)]
pub struct ArbitersAddresses {
    pub trusted_party_arbiter: Address,
    pub trivial_arbiter: Address,
    pub specific_attestation_arbiter: Address,
}

#[derive(Clone)]
pub struct ArbitersClient {
    signer: PrivateKeySigner,
    wallet_provider: WalletProvider,

    pub addresses: ArbitersAddresses,
}

impl Default for ArbitersAddresses {
    fn default() -> Self {
        Self {
            trivial_arbiter: address!("0x8fdbf9C22Ce0B83aFEe8da63F14467663D150b5d"),
            trusted_party_arbiter: address!("0x82FaE516dE4912C382FBF7D9D6d0194b7f532738"),
            specific_attestation_arbiter: address!("0x056034D1D432dD9eA0B7fC20A4375b3A54Ce2e48"),
        }
    }
}

sol! {
    struct TrustedPartyDemandData {
        address creator;
        address baseArbiter;
        bytes baseDemand;
    }
}

sol! {
    struct SpecificAttestationDemandData {
        bytes32 uid;
    }
}

impl ArbitersClient {
    pub async fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<ArbitersAddresses>,
    ) -> eyre::Result<Self> {
        let wallet_provider =
            utils::get_wallet_provider(private_key.clone(), rpc_url.clone()).await?;

        Ok(ArbitersClient {
            signer: private_key.to_string().parse()?,
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub fn encode_trusted_party_demand(demand: TrustedPartyDemandData) -> eyre::Result<Bytes> {
        Ok(demand.abi_encode().into())
    }

    pub fn decode_trusted_party_demand(data: Bytes) -> eyre::Result<TrustedPartyDemandData> {
        Ok(TrustedPartyDemandData::abi_decode(data.as_ref(), true)?)
    }

    pub fn encode_specific_attestation_demand(
        demand: SpecificAttestationDemandData,
    ) -> eyre::Result<Bytes> {
        Ok(demand.abi_encode().into())
    }

    pub fn decode_specific_attestation_demand(
        data: Bytes,
    ) -> eyre::Result<SpecificAttestationDemandData> {
        Ok(SpecificAttestationDemandData::abi_decode(
            data.as_ref(),
            true,
        )?)
    }
}
