use alloy::{
    primitives::{address, Address, Bytes, FixedBytes, Log},
    providers::Provider as _,
    rpc::types::{Filter, TransactionReceipt},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolEvent as _, SolValue as _},
};
use futures_util::StreamExt as _;

use crate::{
    contracts,
    types::{PublicProvider, WalletProvider},
    utils,
};

#[derive(Debug, Clone)]
pub struct ArbitersAddresses {
    pub trusted_party_arbiter: Address,
    pub trivial_arbiter: Address,
    pub specific_attestation_arbiter: Address,
    pub trusted_oracle_arbiter: Address,
}

#[derive(Clone)]
pub struct ArbitersClient {
    signer: PrivateKeySigner,
    public_provider: PublicProvider,
    wallet_provider: WalletProvider,

    pub addresses: ArbitersAddresses,
}

impl Default for ArbitersAddresses {
    fn default() -> Self {
        Self {
            trivial_arbiter: address!("0x8fdbf9C22Ce0B83aFEe8da63F14467663D150b5d"),
            trusted_party_arbiter: address!("0x82FaE516dE4912C382FBF7D9D6d0194b7f532738"),
            specific_attestation_arbiter: address!("0x056034D1D432dD9eA0B7fC20A4375b3A54Ce2e48"),
            trusted_oracle_arbiter: address!("0x8441e4c9eD25C1F2c4d7d191099B6726ADa2D517"),
        }
    }
}

sol! {
    contract TrustedPartyArbiter {
        struct DemandData {
            address creator;
            address baseArbiter;
            bytes baseDemand;
        }
    }
}

sol! {
    contract SpecificAttestationArbiter {
        struct DemandData {
            bytes32 uid;
        }
    }
}

sol! {
    contract TrustedOracleArbiter {
        struct DemandData {
            address oracle;
        }
    }
}

impl ArbitersClient {
    pub async fn new(
        private_key: impl ToString + Clone,
        rpc_url: impl ToString + Clone,
        addresses: Option<ArbitersAddresses>,
    ) -> eyre::Result<Self> {
        let public_provider = utils::get_public_provider(rpc_url.clone()).await?;
        let wallet_provider =
            utils::get_wallet_provider(private_key.clone(), rpc_url.clone()).await?;

        Ok(ArbitersClient {
            signer: private_key.to_string().parse()?,
            public_provider: public_provider.clone(),
            wallet_provider,

            addresses: addresses.unwrap_or_default(),
        })
    }

    pub fn encode_trusted_party_demand(
        demand: TrustedPartyArbiter::DemandData,
    ) -> eyre::Result<Bytes> {
        Ok(demand.abi_encode().into())
    }

    pub fn decode_trusted_party_demand(
        data: Bytes,
    ) -> eyre::Result<TrustedPartyArbiter::DemandData> {
        Ok(TrustedPartyArbiter::DemandData::abi_decode(
            data.as_ref(),
            true,
        )?)
    }

    pub fn encode_specific_attestation_demand(
        demand: SpecificAttestationArbiter::DemandData,
    ) -> eyre::Result<Bytes> {
        Ok(demand.abi_encode().into())
    }

    pub fn decode_specific_attestation_demand(
        data: Bytes,
    ) -> eyre::Result<SpecificAttestationArbiter::DemandData> {
        Ok(SpecificAttestationArbiter::DemandData::abi_decode(
            data.as_ref(),
            true,
        )?)
    }

    pub fn encode_trusted_oracle_demand(
        demand: TrustedOracleArbiter::DemandData,
    ) -> eyre::Result<Bytes> {
        Ok(demand.abi_encode().into())
    }

    pub fn decode_trusted_oracle_demand(
        data: Bytes,
    ) -> eyre::Result<TrustedOracleArbiter::DemandData> {
        Ok(TrustedOracleArbiter::DemandData::abi_decode(
            data.as_ref(),
            true,
        )?)
    }

    pub async fn arbitrate_as_trusted_oracle(
        &self,
        statement: FixedBytes<32>,
        decision: bool,
    ) -> eyre::Result<TransactionReceipt> {
        let trusted_oracle_arbiter = contracts::TrustedOracleArbiter::new(
            self.addresses.trusted_oracle_arbiter,
            &self.wallet_provider,
        );

        let receipt = trusted_oracle_arbiter
            .arbitrate(statement, decision)
            .send()
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    pub async fn wait_for_trusted_oracle_arbitration(
        &self,
        oracle: Address,
        statement: FixedBytes<32>,
        from_block: Option<u64>,
    ) -> eyre::Result<Log<contracts::TrustedOracleArbiter::ArbitrationMade>> {
        let filter = Filter::new()
            .from_block(from_block.unwrap_or(0))
            .address(self.addresses.trusted_oracle_arbiter)
            .event_signature(contracts::TrustedOracleArbiter::ArbitrationMade::SIGNATURE_HASH)
            .topic1(oracle.into_word())
            .topic2(statement);

        let logs = self.public_provider.get_logs(&filter).await?;
        if let Some(log) = logs
            .iter()
            .collect::<Vec<_>>()
            .first()
            .map(|log| log.log_decode::<contracts::TrustedOracleArbiter::ArbitrationMade>())
        {
            return Ok(log?.inner);
        }

        let sub = self.public_provider.subscribe_logs(&filter).await?;
        let mut stream = sub.into_stream();

        if let Some(log) = stream.next().await {
            let log = log.log_decode::<contracts::TrustedOracleArbiter::ArbitrationMade>()?;
            return Ok(log.inner);
        }

        Err(eyre::eyre!("No ArbitrationMade event found"))
    }
}
