use alloy::sol;

// Core
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
    ISchemaRegistry,
    "src/contracts/ISchemaRegistry.json"
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

// Statements
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    ERC20BarterUtils,
    "src/contracts/ERC20BarterUtils.json"
);

pub mod erc20_barter_cross_token {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        ERC20BarterCrossToken,
        "src/contracts/ERC20BarterCrossToken.json"
    );
}

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

pub mod erc721_barter_cross_token {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        ERC721BarterCrossToken,
        "src/contracts/ERC721BarterCrossToken.json"
    );
}

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

pub mod erc1155_barter_cross_token {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        ERC1155BarterCrossToken,
        "src/contracts/ERC1155BarterCrossToken.json"
    );
}

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

pub mod token_bundle {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        TokenBundleEscrowObligation,
        "src/contracts/TokenBundleEscrowObligation.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        TokenBundlePaymentObligation,
        "src/contracts/TokenBundlePaymentObligation.json"
    );
}

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

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    AttestationEscrowObligation2,
    "src/contracts/AttestationEscrowObligation2.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    StringObligation,
    "src/contracts/StringObligation.json"
);

// Arbiters
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    TrivialArbiter,
    "src/contracts/TrivialArbiter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    TrustedPartyArbiter,
    "src/contracts/TrustedPartyArbiter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    UidArbiter,
    "src/contracts/UidArbiter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    RecipientArbiter,
    "src/contracts/RecipientArbiter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    SpecificAttestationArbiter,
    "src/contracts/SpecificAttestationArbiter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    TrustedOracleArbiter,
    "src/contracts/TrustedOracleArbiter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    IntrinsicsArbiter,
    "src/contracts/IntrinsicsArbiter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    IntrinsicsArbiter2,
    "src/contracts/IntrinsicsArbiter2.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    AnyArbiter,
    "src/contracts/AnyArbiter.json"
);

pub mod attester_arbiters {
    use alloy::sol;

    pub mod composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            AttesterArbiterComposing,
            "src/contracts/AttesterArbiterComposing.json"
        );
    }

    pub mod non_composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            AttesterArbiterNonComposing,
            "src/contracts/AttesterArbiterNonComposing.json"
        );
    }
}

pub mod confirmation_arbiters {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        ConfirmationArbiter,
        "src/contracts/ConfirmationArbiter.json"
    );

    pub mod composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            ConfirmationArbiterComposing,
            "src/contracts/ConfirmationArbiterComposing.json"
        );
    }

    pub mod revocable {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            RevocableConfirmationArbiter,
            "src/contracts/RevocableConfirmationArbiter.json"
        );
    }

    pub mod revocable_composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            RevocableConfirmationArbiterComposing,
            "src/contracts/RevocableConfirmationArbiterComposing.json"
        );
    }

    pub mod unrevocable {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            UnrevocableConfirmationArbiter,
            "src/contracts/UnrevocableConfirmationArbiter.json"
        );
    }
}

pub mod payment_fulfillment_arbiters {
    use alloy::sol;

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        ERC1155PaymentFulfillmentArbiter,
        "src/contracts/ERC1155PaymentFulfillmentArbiter.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        ERC20PaymentFulfillmentArbiter,
        "src/contracts/ERC20PaymentFulfillmentArbiter.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        ERC721PaymentFulfillmentArbiter,
        "src/contracts/ERC721PaymentFulfillmentArbiter.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        #[derive(Debug)]
        TokenBundlePaymentFulfillmentArbiter,
        "src/contracts/TokenBundlePaymentFulfillmentArbiter.json"
    );
}

pub mod expiration_time_arbiters {
    use alloy::sol;

    pub mod after {
        use alloy::sol;

        pub mod composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                ExpirationTimeAfterArbiterComposing,
                "src/contracts/ExpirationTimeAfterArbiterComposing.json"
            );
        }

        pub mod non_composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                ExpirationTimeAfterArbiterNonComposing,
                "src/contracts/ExpirationTimeAfterArbiterNonComposing.json"
            );
        }
    }

    pub mod before {
        use alloy::sol;

        pub mod composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                ExpirationTimeBeforeArbiterComposing,
                "src/contracts/ExpirationTimeBeforeArbiterComposing.json"
            );
        }

        pub mod non_composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                ExpirationTimeBeforeArbiterNonComposing,
                "src/contracts/ExpirationTimeBeforeArbiterNonComposing.json"
            );
        }
    }

    pub mod equal {
        use alloy::sol;

        pub mod composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                ExpirationTimeEqualArbiterComposing,
                "src/contracts/ExpirationTimeEqualArbiterComposing.json"
            );
        }

        pub mod non_composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                ExpirationTimeEqualArbiterNonComposing,
                "src/contracts/ExpirationTimeEqualArbiterNonComposing.json"
            );
        }
    }
}

pub mod extended_recipient_arbiters {
    use alloy::sol;

    pub mod composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            RecipientArbiterComposing,
            "src/contracts/RecipientArbiterComposing.json"
        );
    }

    pub mod non_composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            RecipientArbiterNonComposing,
            "src/contracts/RecipientArbiterNonComposing.json"
        );
    }
}

pub mod ref_uid_arbiters {
    use alloy::sol;

    pub mod composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            RefUidArbiterComposing,
            "src/contracts/RefUidArbiterComposing.json"
        );
    }

    pub mod non_composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            RefUidArbiterNonComposing,
            "src/contracts/RefUidArbiterNonComposing.json"
        );
    }
}

pub mod revocable_arbiters {
    use alloy::sol;

    pub mod composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            RevocableArbiterComposing,
            "src/contracts/RevocableArbiterComposing.json"
        );
    }

    pub mod non_composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            RevocableArbiterNonComposing,
            "src/contracts/RevocableArbiterNonComposing.json"
        );
    }
}

pub mod schema_arbiters {
    use alloy::sol;

    pub mod composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            SchemaArbiterComposing,
            "src/contracts/SchemaArbiterComposing.json"
        );
    }

    pub mod non_composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            SchemaArbiterNonComposing,
            "src/contracts/SchemaArbiterNonComposing.json"
        );
    }
}

pub mod time_arbiters {
    use alloy::sol;

    pub mod after {
        use alloy::sol;

        pub mod composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                TimeAfterArbiterComposing,
                "src/contracts/TimeAfterArbiterComposing.json"
            );
        }

        pub mod non_composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                TimeAfterArbiterNonComposing,
                "src/contracts/TimeAfterArbiterNonComposing.json"
            );
        }
    }

    pub mod before {
        use alloy::sol;

        pub mod composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                TimeBeforeArbiterComposing,
                "src/contracts/TimeBeforeArbiterComposing.json"
            );
        }

        pub mod non_composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                TimeBeforeArbiterNonComposing,
                "src/contracts/TimeBeforeArbiter_NonComposing.json"
            );
        }
    }

    pub mod equal {
        use alloy::sol;

        pub mod composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                TimeEqualArbiterComposing,
                "src/contracts/TimeEqualArbiterComposing.json"
            );
        }

        pub mod non_composing {
            use alloy::sol;

            sol!(
                #[allow(missing_docs)]
                #[sol(rpc)]
                #[derive(Debug)]
                TimeEqualArbiterNonComposing,
                "src/contracts/TimeEqualArbiterNonComposing.json"
            );
        }
    }
}

pub mod extended_uid_arbiters {
    use alloy::sol;

    pub mod composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            UidArbiterComposing,
            "src/contracts/UidArbiterComposing.json"
        );
    }

    pub mod non_composing {
        use alloy::sol;

        sol!(
            #[allow(missing_docs)]
            #[sol(rpc)]
            #[derive(Debug)]
            UidArbiterNonComposing,
            "src/contracts/UidArbiterNonComposing.json"
        );
    }
}

// Simple arbiters without naming conflicts
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    NotArbiter,
    "src/contracts/NotArbiter.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    AllArbiter,
    "src/contracts/AllArbiter.json"
);

// Additional contracts
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    JobResultObligation,
    "src/contracts/JobResultObligation.json"
);
