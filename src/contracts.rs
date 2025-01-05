use alloy::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    IEAS,
    "src/contracts/IEAS.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    IERC20,
    "src/contracts/IERC20.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    IERC721,
    "src/contracts/IERC721.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    IERC1155,
    "src/contracts/IERC1155.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC20Permit,
    "src/contracts/ERC20Permit.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC20BarterUtils,
    "src/contracts/ERC20BarterUtils.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC20EscrowObligation,
    "src/contracts/ERC20EscrowObligation.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC20PaymentObligation,
    "src/contracts/ERC20PaymentObligation.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC721BarterUtils,
    "src/contracts/ERC721BarterUtils.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC721EscrowObligation,
    "src/contracts/ERC721EscrowObligation.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC721PaymentObligation,
    "src/contracts/ERC721PaymentObligation.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC1155BarterUtils,
    "src/contracts/ERC1155BarterUtils.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC1155EscrowObligation,
    "src/contracts/ERC1155EscrowObligation.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC1155PaymentObligation,
    "src/contracts/ERC1155PaymentObligation.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    TokenBundleBarterUtils,
    "src/contracts/TokenBundleBarterUtils.json"
);

pub mod token_bundle_standalone {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        AttestationBarterUtils,
        "src/contracts/AttestationBarterUtils.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        AttestationEscrowObligation,
        "src/contracts/AttestationEscrowObligation.json"
    );
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    AttestationEscrowObligation2,
    "src/contracts/AttestationEscrowObligation2.json"
);
