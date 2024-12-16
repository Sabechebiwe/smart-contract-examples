## Data Streams Solana Verifier SDK

A lightweight SDK for creating Solana program instructions to verify Chainlink Data Streams reports, supporting both on-chain and off-chain usage.

### Usage

#### Calculating Required PDA Accounts

```rust
use verify_sdk::VerifierInstructions;

// Inputs
let program_id: Pubkey = // Verifier program ID
let signed_report: Vec<u8> = // Report bytes from Data Streams Off-Chain Server

// Outputs to use in instructions to Verifier program `verify` method
let verifier_account = VerifierInstructions::get_verifier_config_pda(&program_id);
let config_account = VerifierInstructions::get_config_pda(&signed_report, verifier_program_id);
```

#### Creating Instructions

```rust
use verify_sdk::VerifierInstructions;

// Create a verify instruction
let ix = VerifierInstructions::verify(
    &program_id,          // Verifier program ID
    &verifier_account,    // Verifier config account pubkey (previously derived PDA)
    &access_controller,   // Access controller account pubkey
    &user,                // User account (must be signer)
    &config_account,      // Report Config PDA derived from report bytes (prevously derived PDA)
    signed_report,        // Report bytes from Data Streams Off-Chain Server
);
```
