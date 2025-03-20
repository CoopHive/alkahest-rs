use std::env;

use alkahest_rs::{
    clients::{
        arbiters::{ArbitersClient, TrustedPartyArbiter},
        erc20::Erc20Client,
    },
    types::{ApprovalPurpose, ArbiterData, Erc20Data},
    AlkahestClient,
};

use alloy::{
    primitives::{address, FixedBytes},
    sol,
    sol_types::SolValue,
};
use eyre::Result;

#[tokio::test]
async fn test_trade_erc20_for_erc20() -> Result<()> {
    let client_buyer = AlkahestClient::new(
        env::var("PRIVKEY_ALICE")?.as_str(),
        env::var("RPC_URL")?.as_str(),
        None,
    )
    .await?;

    let client_seller = AlkahestClient::new(
        env::var("PRIVKEY_BOB")?.as_str(),
        env::var("RPC_URL")?.as_str(),
        None,
    )
    .await?;

    let usdc = address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e");
    let eurc = address!("0x808456652fdb597867f38412077A9182bf77359F");

    client_buyer
        .erc20
        .approve(
            Erc20Data {
                address: usdc,
                value: 10.try_into()?,
            },
            ApprovalPurpose::Escrow,
        )
        .await?;

    // buy 10 eurc for 10 usdc
    let receipt = client_buyer
        .erc20
        .buy_erc20_for_erc20(
            Erc20Data {
                address: usdc,
                value: 10.try_into()?,
            },
            Erc20Data {
                address: eurc,
                value: 10.try_into()?,
            },
            0,
        )
        .await?;

    let attested = AlkahestClient::get_attested_event(receipt)?;
    println!("{:?}", attested);

    client_seller
        .erc20
        .approve(
            Erc20Data {
                address: eurc,
                value: 10.try_into()?,
            },
            ApprovalPurpose::Payment,
        )
        .await?;

    let receipt = client_seller
        .erc20
        .pay_erc20_for_erc20(attested.uid)
        .await?;
    println!("{:?}", receipt);

    Ok(())
}

#[tokio::test]
async fn test_trade_erc20_for_custom() -> Result<()> {
    let client_buyer = AlkahestClient::new(
        env::var("PRIVKEY_ALICE")?.as_str(),
        env::var("RPC_URL")?.as_str(),
        None,
    )
    .await?;

    let client_seller = AlkahestClient::new(
        env::var("PRIVKEY_BOB")?.as_str(),
        env::var("RPC_URL")?.as_str(),
        None,
    )
    .await?;
    // the example will use JobResultObligation to demand a string to be capitalized
    // but JobResultObligation is generic enough to represent much more (a db query, a Dockerfile...)
    // see https://github.com/CoopHive/alkahest-mocks/blob/main/src/Statements/JobResultObligation.sol
    //
    // for custom cases, you'll have to implement your own arbiter
    //
    // in the example, we'll use TrustedPartyArbiter and TrivialArbiter
    // to make sure the result is from a particular trusted party,
    // without actually validating the result
    // see https://github.com/CoopHive/alkahest-mocks/blob/main/src/Validators/TrustedPartyArbiter.sol
    // and https://github.com/CoopHive/alkahest-mocks/blob/main/src/Validators/TrivialArbiter.sol

    // construct custom demand. note that this could be anything, and is determined by the arbiter.
    // since our base arbiter is TrivialArbiter, which doesn't actually decode DemandData,
    // the format doesn't matter. though the seller and buyer do still have to agree on it
    // so that the seller can properly fulfill the demand.
    sol! {
        struct ResultDemandData {
            string query;
        }
    }
    let base_demand = ResultDemandData {
        query: "hello world".to_string(),
    }
    .abi_encode();

    // we use TrustedPartyArbiter to wrap the base demand. This actually does decode DemandData,
    // and we use the DemandData format it defines,
    // to demand that only our trusted seller can fulfill the demand.
    // if the baseDemand were something other than TrivialArbiter,
    // it would be an additional check on the fulfillment.
    // many arbiters can be stacked according to this pattern.
    // if using a custom Arbiter not supported by the SDK, you can use the sol! macro and abi_encode
    // directly, like we did for the base_demand

    let demand = ArbitersClient::encode_trusted_party_demand(TrustedPartyArbiter::DemandData {
        creator: client_seller.address,
        baseArbiter: client_seller.arbiters.addresses.trivial_arbiter,
        baseDemand: base_demand.into(),
    });

    // approve escrow contract to spend tokens
    let usdc = address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e");
    client_buyer
        .erc20
        .approve(
            Erc20Data {
                address: usdc,
                value: 10.try_into()?,
            },
            ApprovalPurpose::Escrow,
        )
        .await?;

    // make escrow with generic escrow function,
    // passing in TrustedPartyArbiter's address and our custom demand,
    // and no expiration
    let escrow = client_buyer
        .erc20
        .buy_with_erc20(
            Erc20Data {
                address: usdc,
                value: 10.try_into()?,
            },
            ArbiterData {
                arbiter: client_seller.arbiters.addresses.trusted_party_arbiter,
                demand,
            },
            0,
        )
        .await?;
    let escrow = AlkahestClient::get_attested_event(escrow)?;
    println!("escrow: {escrow:?}");

    // now the seller manually decodes the statement and demand
    // and creates a StringResultObligation
    // and manually collects payment
    let buy_statement = client_seller
        .attestation
        .get_attestation(escrow.uid)
        .await?;
    let buy_statement = Erc20Client::decode_escrow_statement(buy_statement.data)?;

    let decoded_demand = ArbitersClient::decode_trusted_party_demand(buy_statement.demand)?;
    let decoded_base_demand =
        ResultDemandData::abi_decode(decoded_demand.baseDemand.as_ref(), true);

    // uppercase string for the example;
    // this could be anything as agreed upon between buyer and seller
    // (running a Docker job, executing a DB query...)
    // as long as the job "spec" is agreed upon between buyer and seller,
    // and the "query" is contained in the demand
    let result = decoded_base_demand?.query.to_uppercase();
    println!("result: {}", result);

    // manually make result statement
    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        JobResultObligation,
        "src/contracts/JobResultObligation.json"
    );

    // JobResultObligation.StatementData:
    // struct StatementData {
    //     string result;
    // }
    //
    // JobResultObligation.makeStatement
    // function makeStatement(
    //     StatementData calldata data,
    //     bytes32 refUID
    // ) public returns (bytes32)
    let job_result_obligation = address!("0x823a06994B4e817a5127c042dBd2742CcFdF2076");
    let job_result_obligation =
        JobResultObligation::new(job_result_obligation, &client_seller.wallet_provider);

    let result = job_result_obligation
        .makeStatement(
            JobResultObligation::StatementData {
                result: result.to_string(),
            },
            FixedBytes::<32>::ZERO,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    let result = AlkahestClient::get_attested_event(result)?;
    println!("result: {result:?}");

    // and collect the payment from escrow
    let collection = client_seller
        .erc20
        .collect_payment(escrow.uid, result.uid)
        .await?;
    println!("collection: {collection:?}");

    // meanwhile, the buyer can wait for fulfillment of her escrow.
    // if called after fulfillment, like in this case, it will
    // return the fulfilling statement immediately
    let fulfillment = client_buyer
        .wait_for_fulfillment(
            client_buyer.erc20.addresses.escrow_obligation,
            escrow.uid,
            None,
        )
        .await?;

    // and extract the result from the fulfillment statement
    let fulfillment = client_buyer
        .attestation
        .get_attestation(fulfillment.fulfillment)
        .await?;

    let result = JobResultObligation::StatementData::abi_decode(fulfillment.data.as_ref(), true);
    println!("result: {}", result?.result);

    Ok(())
}
