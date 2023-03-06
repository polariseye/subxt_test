use std::collections::HashMap;
use std::str::FromStr;
use codec::{Compact, Encode};
use jsonrpsee::client_transport::ws::Uri;
use sp_core::crypto::Ss58Codec;
use sp_core::{ByteArray, Bytes, Decode, Pair};
use sp_keyring::AccountKeyring;
use subxt::{OnlineClient, PolkadotConfig};
use subxt::config::ExtrinsicParams;
use subxt::tx::{SubmittableExtrinsic, TxPayload};
use subxt::utils::{AccountId32, MultiAddress, MultiSignature};
use tracing_subscriber::FmtSubscriber;
use tracing::Level;
const ADDR_1:&str="5DkA4a1H8HfqjUpSm8JKJYGXdHX6BQ5eUo5NFSa3VzpHGVDM";
const PUB_KEY_1:&str="4a5304cd8eba56c8dc6f6b6ba91b89294572e8a8312f6f2839f8685aa0f90a2b";
const SECRET_1:&str="975ecdda71e25ab75ec5d15ac362889c381a849c46344f24efa6139c513ea8c6";

const ADDR_2:&str="5Dw1dQV6zFopC52H4D3hw366WFb9DpueC91hA9KoJSuP4qqV";
const PUB_KEY_2:&str="529a53c953c69d2144d0a9515ece42f6de4a00fe0a68135a7c7423517c9d4902";
const SECRET_2:&str="1b7185e8a4082518b560f004ac2031f72b254d621fb318e99f9c6f27514e006a";

#[tokio::main]
async fn main() {
    let log_files = std::fs::File::create("./local_log.txt").unwrap();
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::TRACE)
        .with_writer(log_files)
        // completes the builder.
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    get_balance_test().await;
}

#[subxt::subxt(runtime_metadata_path = "artifacts/westend.scale")]
mod polkadot {}

async fn generate_address(){
    let (pair,seed)= sp_core::sr25519::Pair::generate();
    let pub_key= pair.public().to_vec();

    println!("secret:{}", hex::encode( &seed.to_vec()));
    println!("public key :{}", hex::encode(pair.public().as_slice()));

    let account_id = sp_core::crypto::AccountId32::from_slice(pub_key.as_slice()).expect("convert to accountId error");

    println!("address :{}", account_id.to_ss58check());
}

async fn create_client(){
    let _client_obj = jsonrpsee::ws_client::WsClientBuilder::default().build("wss://westend-rpc.polkadot.io:443").await.unwrap();
}

async fn get_balance_test(){
    let api = subxt::OnlineClient::<PolkadotConfig>
    ::from_url("wss://westend-rpc.polkadot.io:443")
        .await.unwrap();

    let addr= AccountId32::from_str(ADDR_1).expect("addr convert error");

    let storage_address = polkadot::storage().system().account(&addr);


    let result = api.storage().at(None).await.unwrap().fetch_or_default(&storage_address).await.unwrap();
    // let result = api
    //     .storage()
    //     .system()
    //     .account(&addr,None)
    //     .await
    //     .unwrap();
    println!("nonce:{}",result.nonce.to_string());
    println!("free:{}",result.data.free.to_string());
    println!("reserved:{}",result.data.reserved.to_string());
    println!("misc_frozen:{}",result.data.misc_frozen.to_string());
    println!("fee_frozen:{}",result.data.fee_frozen.to_string());
}

async fn transfer_test2(){
    let api = subxt::OnlineClient::<PolkadotConfig>
    ::from_url("wss://westend-rpc.polkadot.io:443")
        .await.unwrap();

    let from_secret= SECRET_1;
    let from_addr= AccountId32::from_str(ADDR_1).expect("addr convert error");
    let to_address= AccountId32::from_str(ADDR_2).expect("addr convert error");
    let amount= u128::from_str("1000000000000").expect("amount convert error");
    let signer =  sp_core::sr25519::Pair::from_seed_slice(&hex::decode(from_secret).unwrap()).unwrap();

    // Configure the transaction tip and era:
    /*
    let _tx_params = SubstrateExtrinsicParamsBuilder::new()
        .tip(AssetTip::new(20_000_000_000))
        .era(Era::Immortal, *api.client.genesis());
    */

    let signer= subxt::tx::PairSigner::<PolkadotConfig,_>::new(signer);

    let tx = polkadot::tx().balances()
        .transfer(MultiAddress::Id(to_address), amount);

    let tx_hash = api.tx().sign_and_submit_default(&tx, &signer).await.unwrap();
    println!("tx hash:{}",hex::encode(&tx_hash.encode()));
}

async fn transfer_test(){
    let api = subxt::OnlineClient::<PolkadotConfig>
    ::from_url("wss://westend-rpc.polkadot.io:443")
        .await.unwrap();

    let from_secret=SECRET_1;
    let from_addr= AccountId32::from_str(ADDR_1).expect("addr convert error");
    let storage_address = polkadot::storage().system().account(&from_addr);
    let result = api.storage().at(None).await.unwrap().fetch_or_default(&storage_address).await.unwrap();

    let to_address= AccountId32::from_str(ADDR_2).expect("addr convert error");
    let amount=u128::from_str("1000000000000").expect("amount convert error");
    let caller = polkadot::tx().balances()
        .transfer(MultiAddress::Id(to_address.clone()), amount);
    let nonce = result.nonce;
    println!("nonce:{}",nonce);
    let unsigned= convert_to_unsigned(nonce, caller,&api, Default::default()).await.expect("convert to unsigned error");
    println!("unsigned:{}",hex::encode(&unsigned));

    let signer= sp_core::sr25519::Pair::from_seed_slice(&hex::decode(from_secret).unwrap()).expect("sr25519 from seed error");
    let mut sign= signer.sign(&unsigned).0.to_vec();
    // println!("sign result:{}",hex::encode(&sign));

    let mut sign_bytes = [0u8;64];
    sign_bytes.copy_from_slice(&sign);
    let sign = MultiSignature::Sr25519(sign_bytes);
    // sign.insert(0,0x01u8); // 1代表 sr25519

    let caller = polkadot::tx().balances()
        .transfer(MultiAddress::Id(to_address), amount);

    let tx_hash=  commit_unsigned(nonce,&MultiAddress::Id(from_addr.clone()),sign, caller,&api, Default::default()).await.expect("commit error");
    println!("tx hash!!:{}",tx_hash);
}

async fn convert_to_unsigned<C: TxPayload + Send + Sync, Config:subxt::Config>(nonce: Config::Index,caller:C,api:&OnlineClient<Config>, other_param: <Config::ExtrinsicParams as ExtrinsicParams<Config::Index, Config::Hash>>::OtherParams)->Result<Vec<u8>,subxt::Error>{
    // 2. SCALE encode call data to bytes (pallet u8, call u8, call params).
    let call_data = {
        let metadata = api.offline().metadata();
        subxt::utils::Encoded(caller.encode_call_data(&metadata).unwrap())
    };

    // 3. Construct our custom additional/extra params.
    let additional_and_extra_params = {
        // Obtain spec version and transaction version from the runtime version of the client.

        let offline_client = api.offline();
        let runtime= offline_client.runtime_version();
        let genesis_hash= offline_client.genesis_hash();
        <Config::ExtrinsicParams as ExtrinsicParams<Config::Index, Config::Hash>>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            genesis_hash,
            other_param,
        )
    };

    // 4. Construct signature. This is compatible with the Encode impl
    //    for SignedPayload (which is this payload of bytes that we'd like)
    //    to sign. See:
    //    https://github.com/paritytech/substrate/blob/9a6d706d8db00abb6ba183839ec98ecd9924b1f8/primitives/runtime/src/generic/unchecked_extrinsic.rs#L215)
    let mut bytes = Vec::new();
    call_data.encode_to(&mut bytes);
    println!("call_data:{}",hex::encode(&bytes));
    additional_and_extra_params.encode_extra_to(&mut bytes);
    println!("additional_and_extra_params.encode_extra_to:{}",hex::encode(&bytes));
    additional_and_extra_params.encode_additional_to(&mut bytes);
    println!("additional_and_extra_params.encode_additional_to:{}",hex::encode(&bytes));
    if bytes.len() > 256 {
        return Ok(sp_core::blake2_256(&bytes).to_vec());
    } else {
        return Ok(bytes);
    }
}

async fn commit_unsigned<C: TxPayload + Send + Sync,Config:subxt::Config>(nonce:Config::Index, sender_address:&Config::Address, signature:Config::Signature,
                                                                     caller:C,api:&OnlineClient<Config>,other_param:<Config::ExtrinsicParams as ExtrinsicParams<Config::Index, Config::Hash>>::OtherParams)->Result<String,subxt::Error>{
    // 2. SCALE encode call data to bytes (pallet u8, call u8, call params).
    let call_data = {
        let metadata = api.offline().metadata();
        subxt::utils::Encoded(caller.encode_call_data(&metadata).unwrap())
    };

    // 3. Construct our custom additional/extra params.
    let additional_and_extra_params = {
        // Obtain spec version and transaction version from the runtime version of the client.

        let offline_client = api.offline();
        let runtime= offline_client.runtime_version();
        let genesis_hash= offline_client.genesis_hash();
        <Config::ExtrinsicParams as ExtrinsicParams<Config::Index, Config::Hash>>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            genesis_hash,
            other_param,
        )
    };

    // println!("xt signature: {}", hex::encode(signature.));

    // 5. Encode extrinsic, now that we have the parts we need. This is compatible
    //    with the Encode impl for UncheckedExtrinsic (protocol version 4).
    let extrinsic = {
        let mut encoded_inner = Vec::new();
        // "is signed" + transaction protocol version (4)
        (0b10000000 + 4u8).encode_to(&mut encoded_inner);
        // from address for signature
        sender_address.encode_to(&mut encoded_inner);
        // the signature bytes
        signature.encode_to(&mut encoded_inner);
        // attach custom extra params
        additional_and_extra_params.encode_extra_to(&mut encoded_inner);
        // and now, call data
        call_data.encode_to(&mut encoded_inner);
        // now, prefix byte length:
        let len = Compact(
            u32::try_from(encoded_inner.len())
                .expect("extrinsic size expected to be <4GB"),
        );
        let mut encoded = Vec::new();
        len.encode_to(&mut encoded);
        encoded.extend(encoded_inner);
        encoded
    };

    // Wrap in Encoded to ensure that any more "encode" calls leave it in the right state.
    // maybe we can just return the raw bytes..
    println!("extrinsic bytes:{}",hex::encode(&extrinsic));
        let tx_hash = SubmittableExtrinsic::from_bytes(
            api.clone(),
            extrinsic,
        ).submit().await.unwrap();
    Ok(hex::encode(tx_hash.as_ref()))
    //println!("tx hash:{}",hex::encode(&Encoded(extrinsic).encode()));

    //Ok("".to_string())
}

async fn get_fee_info(){
    let api = subxt::OnlineClient::<PolkadotConfig>
    ::from_url("wss://westend-rpc.polkadot.io:443")
        .await.unwrap();
    const ADDR_1:&str="5GE2SqrRB7rbM1uKkogqkFT6m6xjn7KD2MQ6r6PLCvfT6Zba";
    const ADDR_2:&str="5FsAMJ4Co89NGkKguhb7GG7K4WSoQzy9SAPoEQtnRoJdK2Bb";
    let from_secret=SECRET_1;
    let from_addr= subxt::utils::AccountId32::from_str(ADDR_1).expect("addr convert error");
    let storage_address = polkadot::storage().system().account(&from_addr);
    let result = api.storage().at(None).await.unwrap().fetch_or_default(&storage_address).await.unwrap();

    let to_address= subxt::utils::AccountId32::from_str(ADDR_2).expect("addr convert error");
    let amount=u128::from_str("10000000000").expect("amount convert error");

    println!("to:{} amount:{}", hex::encode(&to_address.0), amount);
    let caller = polkadot::tx().balances()
        .transfer(MultiAddress::Id(to_address), amount);

    let from_addr = MultiAddress::Id(from_addr);
    let extrinisc= get_empty_extrinisc(result.nonce, &from_addr, &caller, &api, Default::default()).await.expect("get extrinisc error");
    println!("extrinisc bytes:{}", hex::encode(&extrinisc));
    let extrinisc:Bytes= extrinisc.into();

    let params= subxt::rpc::rpc_params![extrinisc];
    // let params = subxt::rpc::RpcParams(extrinisc.as_ref().to_vec());

    match api.rpc()
        .request::<serde_json::Value>("payment_queryInfo", params)
        .await{
        Ok(val)=>{
            println!("result:{:?}",val);
        },
        Err(err)=>{
            println!("err:{}",err.to_string());
        }
    }
}
async fn get_empty_extrinisc<C: TxPayload + Send + Sync,Config:subxt::Config>(nonce:Config::Index,sender_address:&Config::Address,caller:&C,api:&OnlineClient<Config>,
                                                                              other_param:<Config::ExtrinsicParams as ExtrinsicParams<Config::Index, Config::Hash>>::OtherParams)->Result<Vec<u8>,subxt::Error>{
    // 2. SCALE encode call data to bytes (pallet u8, call u8, call params).
    let call_data = {
        let metadata = api.offline().metadata();
        subxt::utils::Encoded(caller.encode_call_data(&metadata).unwrap())
    };
    println!("call_data:{}", hex::encode(&call_data.0));

    // 3. Construct our custom additional/extra params.
    let additional_and_extra_params = {
        // Obtain spec version and transaction version from the runtime version of the client.

        let offline_client = api.offline();
        let runtime= offline_client.runtime_version();
        let genesis_hash= offline_client.genesis_hash();
        println!("nonce:{:?} spec_version:{} transaction_version:{} genesis:{:?}", nonce, runtime.spec_version, runtime.transaction_version, genesis_hash);
        <Config::ExtrinsicParams as ExtrinsicParams<Config::Index, Config::Hash>>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            genesis_hash,
            other_param,
        )
    };
    println!("nonce:{:?}", additional_and_extra_params);

    // 5. Encode extrinsic, now that we have the parts we need. This is compatible
    //    with the Encode impl for UncheckedExtrinsic (protocol version 4).
    let signature=[1u8;65];
    let extrinsic = {
        let mut encoded_inner = Vec::new();
        // "is signed" + transaction protocol version (4)
        (0b10000000 + 4u8).encode_to(&mut encoded_inner);
        // from address for signature
        sender_address.encode_to(&mut encoded_inner);
        println!("added sender_address:{}",hex::encode(&encoded_inner));
        // the signature bytes
        signature.encode_to(&mut encoded_inner);
        println!("added signature:{}",hex::encode(&encoded_inner));
        // attach custom extra params
        additional_and_extra_params.encode_extra_to(&mut encoded_inner);
        // and now, call data
        call_data.encode_to(&mut encoded_inner);
        // now, prefix byte length:
        let len = Compact(
            u32::try_from(encoded_inner.len())
                .expect("extrinsic size expected to be <4GB"),
        );
        let mut encoded = Vec::new();
        len.encode_to(&mut encoded);
        encoded.extend(encoded_inner);
        encoded
    };

    // Wrap in Encoded to ensure that any more "encode" calls leave it in the right state.
    // maybe we can just return the raw bytes..
    Ok(extrinsic)
    //println!("tx hash:{}",hex::encode(&Encoded(extrinsic).encode()));

    //Ok("".to_string())
}

async fn get_block_hash(){
    let api = subxt::OnlineClient::<PolkadotConfig>
    ::from_url("wss://westend-rpc.polkadot.io:443")
        .await.unwrap();

    let storage_address = polkadot::storage().system().block_hash(&11201u32);

    let result = api.storage().at(None).await.unwrap().fetch_or_default(&storage_address).await.unwrap();
    println!("result:{}", result);
}