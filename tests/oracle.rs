#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{Address, Bytes, FixedBytes, bytes},
        providers::Provider as _,
        sol,
        sol_types::SolValue,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    use {
        alkahest_rs::clients::arbiters::{
            ArbitersClient, IntrinsicsArbiter2, MultiArbiter, RecipientArbiterNoncomposing,
            SpecificAttestationArbiter, TrustedOracleArbiter, TrustedPartyArbiter,
            UidArbiterComposing,
        },
        alkahest_rs::contracts,
        alkahest_rs::utils::setup_test_environment,
    };

    #[tokio::test]
    async fn test_arbitrate_past() -> eyre::Result<()> {
        let test = setup_test_environment().await?;

        // Create demand data with oracle as bob
        let demand_data = TrustedOracleArbiter::DemandData {
            oracle: test.bob.address(),
            data: bytes!(""),
        };

        // Encode demand data
        let demand = ArbitersClient::encode_trusted_oracle_demand(&demand_data);

        Ok(())
    }
}
