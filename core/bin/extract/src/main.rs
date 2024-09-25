use anyhow::Result;
use anyhow::{bail, Context};
use std::fs::File;
use std::io::Write;
use tracing_log::LogTracer;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};
use zksync_dal::{ConnectionPool, Core, CoreDal};
use zksync_prover_interface::inputs::{
    TeeVerifierInput, V1TeeVerifierInput, WitnessInputMerklePaths,
};
use zksync_tee_verifier::Verify;
use zksync_types::url::SensitiveUrl;
use zksync_types::{L1BatchNumber, L2ChainId};
use zksync_utils::u256_to_h256;
use zksync_vm_executor::storage::L1BatchParamsProvider;

#[tokio::main]
async fn main() -> Result<()> {
    LogTracer::init().context("Failed to set logger")?;

    let subscriber = Registry::default()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).context("Failed to set logger")?;
    let l1_batch_number = L1BatchNumber(10530);
    // produce_input(l1_batch_number).await?;

    let tee_verifier_input: TeeVerifierInput = {
        use std::fs::File;
        use std::io::Read;
        let filename =
            format!("tee_verifier_inputs_tee_verifier_input_for_l1_batch_{l1_batch_number}.bin");

        let mut file = File::open(&filename).context(format!("failed to open {filename}"))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .context("failed to read tee_verifier_input.bin")?;
        bincode::deserialize(&buffer).context("failed to deserialize binary contents")?
    };

    match tee_verifier_input {
        TeeVerifierInput::V1(tvi) => {
            tvi.verify()?;
        }
        _ => bail!("error!"),
    }
    Ok(())
}

async fn produce_input(l1_batch_number: L1BatchNumber) -> Result<()> {
    let l2_chain_id: L2ChainId = L2ChainId::from(300);
    let username = std::env::var("PGUSER")?;
    let password = std::env::var("PGPASSWORD")?;
    let hostname = std::env::var("PGHOSTNAME")?;
    let dbname = std::env::var("PGDBNAME")?;
    let url: SensitiveUrl =
        format!("postgres://{username}:{password}@{hostname}/{dbname}").parse()?;

    let connection_pool = ConnectionPool::<Core>::builder(url, 3).build().await?;

    let prepare_basic_circuits_job: WitnessInputMerklePaths = {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(format!(
            "witness_inputs_merkel_tree_paths_{l1_batch_number}.bin"
        ))
        .context("failed to open test.bin")?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .context("failed to read test.bin")?;
        bincode::deserialize(&buffer).context("failed to deserialize binary contents")?
    };

    let mut connection = connection_pool
        .connection()
        .await
        .context("failed to get connection for TeeVerifierInputProducer")?;

    let l2_blocks_execution_data = connection
        .transactions_dal()
        .get_l2_blocks_to_execute_for_l1_batch(l1_batch_number)
        .await?;

    let l1_batch_header = connection
        .blocks_dal()
        .get_l1_batch_header(l1_batch_number)
        .await
        .with_context(|| format!("header is missing for L1 batch #{l1_batch_number}"))?
        .unwrap();

    let mut l1_batch_params_provider = L1BatchParamsProvider::new();
    l1_batch_params_provider
        .initialize(&mut connection)
        .await
        .context("failed initializing L1 batch params provider")?;

    let first_miniblock_in_batch = l1_batch_params_provider
        .load_first_l2_block_in_batch(&mut connection, l1_batch_number)
        .await
        .with_context(|| format!("failed loading first miniblock in L1 batch #{l1_batch_number}"))?
        .with_context(|| format!("no miniblocks persisted for L1 batch #{l1_batch_number}"))?;

    // In the state keeper, this value is used to reject execution.
    // All batches have already been executed by State Keeper.
    // This means we don't want to reject any execution, therefore we're using MAX as an allow all.
    let validation_computational_gas_limit = u32::MAX;

    let (system_env, l1_batch_env) = l1_batch_params_provider
        .load_l1_batch_params(
            &mut connection,
            &first_miniblock_in_batch,
            validation_computational_gas_limit,
            l2_chain_id,
        )
        .await
        .context("expected miniblock to be executed and sealed")?;

    let used_contract_hashes = l1_batch_header
        .used_contract_hashes
        .into_iter()
        .map(u256_to_h256)
        .collect();

    // `get_factory_deps()` returns the bytecode in chunks of `Vec<[u8; 32]>`,
    // but `fn store_factory_dep(&mut self, hash: H256, bytecode: Vec<u8>)` in `InMemoryStorage` wants flat byte vecs.
    pub fn into_flattened<T: Clone, const N: usize>(data: Vec<[T; N]>) -> Vec<T> {
        let mut new = Vec::new();
        for slice in data.iter() {
            new.extend_from_slice(slice);
        }
        new
    }

    let used_contracts = connection
        .factory_deps_dal()
        .get_factory_deps(&used_contract_hashes)
        .await
        .into_iter()
        .map(|(hash, bytes)| (u256_to_h256(hash), into_flattened(bytes)))
        .collect();

    tracing::info!("Started execution of l1_batch: {l1_batch_number:?}");

    let tee_verifier_input = V1TeeVerifierInput::new(
        prepare_basic_circuits_job,
        l2_blocks_execution_data,
        l1_batch_env,
        system_env,
        used_contracts,
    );

    let tee_verifier_input = TeeVerifierInput::new(tee_verifier_input);

    // Serialize and save l2_blocks_execution_data to a file
    let serialized_data = bincode::serialize(&tee_verifier_input)?;
    let filename =
        format!("tee_verifier_inputs_tee_verifier_input_for_l1_batch_{l1_batch_number}.bin");
    let mut file = File::create(&filename).context(format!("failed to create {filename}"))?;
    file.write_all(&serialized_data)
        .context("failed to write tee_verifier_input to file")?;

    Ok(())
}
