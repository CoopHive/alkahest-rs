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
    addresses::FILECOIN_CALIBRATION_ADDRESSES,
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
        FILECOIN_CALIBRATION_ADDRESSES.arbiters_addresses.unwrap()
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

    pub fn encode_trusted_party_demand(demand: TrustedPartyArbiter::DemandData) -> Bytes {
        demand.abi_encode().into()
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
    ) -> Bytes {
        demand.abi_encode().into()
    }

    pub fn decode_specific_attestation_demand(
        data: Bytes,
    ) -> eyre::Result<SpecificAttestationArbiter::DemandData> {
        Ok(SpecificAttestationArbiter::DemandData::abi_decode(
            data.as_ref(),
            true,
        )?)
    }

    pub fn encode_trusted_oracle_demand(demand: TrustedOracleArbiter::DemandData) -> Bytes {
        demand.abi_encode().into()
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
