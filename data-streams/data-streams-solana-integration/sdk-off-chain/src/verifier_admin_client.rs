use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::system_program;
use anchor_lang::{solana_program, InstructionData, ToAccountMetas};
use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_client::rpc_request::RpcError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use verifier::accounts::{
    AcceptOwnershipContext, InitializeAccountDataContext, InitializeContext, ReallocContext,
    SetAccessControllerContext, TransferOwnershipContext, UpdateConfigContext,
};
use verifier::instruction::{
    AcceptOwnership as AcceptOwnershipInstruction, Initialize as InitializeInstruction,
    InitializeAccountData as InitializeAccountDataInstruction,
    ReallocAccount as ReallocInstruction, RemoveLatestConfig as RemoveLatestConfigInstruction,
    SetAccessController as SetAccessControllerInstruction, SetConfig as SetConfigInstruction,
    SetConfigActive as SetConfigActiveInstruction,
    SetConfigWithActivationTime as SetConfigWithActivationTimeInstruction,
    TransferOwnership as TransferOwnershipInstruction,
};
use verifier::state::VerifierAccount;
use verifier::util::Compressor;

use data_streams_solana_verifier_sdk::VerifierInstructions;

pub struct VerifierAdminClient {
    program_id: Pubkey,
    verifier_data_account: Pubkey,
    access_controller_data_account: Option<Pubkey>,
    rpc_client: RpcClient,
    payer: Keypair,
}

impl VerifierAdminClient {
    pub fn new(
        program_id: Pubkey,
        access_controller_data_account: Option<Pubkey>,
        rpc_client: RpcClient,
        payer: Keypair,
    ) -> Self {
        let (data_account, _bump) = Pubkey::find_program_address(&[b"verifier"], &program_id);
        Self {
            program_id,
            verifier_data_account: data_account,
            access_controller_data_account,
            rpc_client,
            payer,
        }
    }

    pub fn initialize(&self) -> Result<Signature, ClientError> {
        let data = InitializeInstruction {};

        let initialize_context = InitializeContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
            program: self.program_id,
            program_data: self.get_program_data_address(),
            system_program: system_program::ID,
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: initialize_context.to_account_metas(None),
            data: data.data(),
        };

        println!("Initializing verifier account: {}", self.verifier_data_account);

        self.send_transaction(&[instruction], &[&self.payer])
    }

    /// This will reallocate the account to the full size required for the verifier account
    /// using multiple realloc transaction calls
    pub fn realloc_full_size(&self) -> Result<Signature, ClientError> {
        const ACCOUNT_DISCRIMINATOR_SIZE: usize = 8;
        const REALLOC_INCREMENT: usize = 10 * 1024;

        let target_size = ACCOUNT_DISCRIMINATOR_SIZE + std::mem::size_of::<VerifierAccount>();

        // Get current account size
        let current_account = self.rpc_client
            .get_account(&self.verifier_data_account)
            .expect("Failed to get verifier account from RPC");

        let mut current_size = current_account.data.len();

        // Perform reallocation in increments
        while current_size < target_size {
            println!("Current size: {}", current_size);
            current_size = std::cmp::min(current_size + REALLOC_INCREMENT, target_size);
            println!("Reallocating to size: {}", current_size);
            let signature = self.realloc(current_size)?;
            if current_size >= target_size {
                return Ok(signature);
            }
        }

        unreachable!("Loop must either return a signature or propagate an error")
    }

    pub fn realloc(&self, len: usize) -> Result<Signature, ClientError> {
        let _len = len as u32;
        let data = ReallocInstruction { _len };

        let realloc_context = ReallocContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
            program: self.program_id,
            program_data: self.get_program_data_address(),
            system_program: system_program::ID,
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: realloc_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn init_data(&self) -> Result<Signature, ClientError> {
        let data = InitializeAccountDataInstruction {};

        let ctx = InitializeAccountDataContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
            access_controller: self.access_controller_data_account,
            program: self.program_id,
            program_data: self.get_program_data_address(),
            system_program: system_program::ID,
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: ctx.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn set_access_controller(
        &self,
        new_access_controller: Option<Pubkey>,
    ) -> Result<Signature, ClientError> {
        let data = SetAccessControllerInstruction {};

        let set_access_controller_context = SetAccessControllerContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
            access_controller: new_access_controller,
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: set_access_controller_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn verify(&self, signed_report: Vec<u8>) -> Result<Signature, ClientError> {
        let access_controller = self.access_controller_data_account.ok_or_else(|| {
            RpcError::RpcRequestError("AccessController is required for verification".to_string())
        })?;

        let config_account = self.compute_report_config_pda(&signed_report);

        // Compress the report before sending. Obtain this off-chain data streams server
        let compressed_report = Compressor::compress(&signed_report);

        let instruction = VerifierInstructions::verify(
            &self.program_id,
            &self.verifier_data_account,
            &access_controller,
            &self.payer.pubkey(),
            &config_account,
            compressed_report,
        );

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn set_config_with_activation_time(
        &self,
        signers: Vec<[u8; 20]>,
        f: u8,
        activation_time: u32,
    ) -> Result<Signature, ClientError> {
        let data = SetConfigWithActivationTimeInstruction {
            signers,
            f,
            activation_time,
        };

        let update_config_context = UpdateConfigContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: update_config_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn set_config(&self, signers: Vec<[u8; 20]>, f: u8) -> Result<Signature, ClientError> {
        let data = SetConfigInstruction { signers, f };

        let update_config_context = UpdateConfigContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: update_config_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn set_config_active(
        &self,
        don_config_index: u64,
        is_active: bool,
    ) -> Result<Signature, ClientError> {
        let data = SetConfigActiveInstruction {
            don_config_index,
            is_active: u8::from(is_active),
        };

        let update_config_context = UpdateConfigContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: update_config_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn remove_latest_config(&self) -> Result<Signature, ClientError> {
        let data = RemoveLatestConfigInstruction {};

        let update_config_context = UpdateConfigContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: update_config_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn transfer_ownership(&self, proposed_owner: Pubkey) -> Result<Signature, ClientError> {
        let data = TransferOwnershipInstruction { proposed_owner };

        let transfer_ownership_context = TransferOwnershipContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: transfer_ownership_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    pub fn accept_ownership(&self) -> Result<Signature, ClientError> {
        let data = AcceptOwnershipInstruction {};

        let accept_ownership_context = AcceptOwnershipContext {
            verifier_account: self.verifier_data_account,
            owner: self.payer.pubkey(),
        };

        let instruction = Instruction {
            program_id: self.program_id,
            accounts: accept_ownership_context.to_account_metas(None),
            data: data.data(),
        };

        self.send_transaction(&[instruction], &[&self.payer])
    }

    fn send_transaction(
        &self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> Result<Signature, ClientError> {
        // Fetch the latest blockhash
        let recent_blockhash = self.rpc_client.get_latest_blockhash()?;

        // Create the transaction
        let mut transaction = Transaction::new_with_payer(instructions, Some(&self.payer.pubkey()));
        transaction.sign(signers, recent_blockhash);

        // Send and confirm the transaction
        self.rpc_client
            .send_and_confirm_transaction(&transaction)
    }

    /// Gets the account size in bytes
    pub fn get_account_size_requirement() -> usize {
        size_of::<VerifierAccount>() + 8 // Add 8 bytes for discriminator
    }

    fn compute_report_config_pda(&self, report: &[u8]) -> Pubkey {
        let seed = &report[..32];
        Pubkey::find_program_address(&[seed], &self.program_id).0
    }

    fn get_program_data_address(&self) -> Pubkey {
        let (program_data_address, _) = Pubkey::find_program_address(
            &[self.program_id.as_ref()],
            &solana_program::bpf_loader_upgradeable::id(),
        );
        program_data_address
    }
}
