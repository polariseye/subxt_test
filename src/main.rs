use std::collections::HashMap;
use std::str::FromStr;
use codec::Encode;
use jsonrpsee::core::__reexports::serde_json;
use sp_core::crypto::Ss58Codec;
use sp_core::{ByteArray, Bytes, Decode, Pair};
use sp_keyring::AccountKeyring;
use subxt::*;
use subxt::extrinsic::{AssetTip, Era, ExtrinsicParams, PlainTip};
use subxt::rpc::JsonValue;
use tracing_subscriber::FmtSubscriber;
use tracing::Level;
use subxt::rpc::ClientT;
const ADDR_1:&str="5DkA4a1H8HfqjUpSm8JKJYGXdHX6BQ5eUo5NFSa3VzpHGVDM";
const PUB_KEY_1:&str="4a5304cd8eba56c8dc6f6b6ba91b89294572e8a8312f6f2839f8685aa0f90a2b";
const SECRET_1:&str="975ecdda71e25ab75ec5d15ac362889c381a849c46344f24efa6139c513ea8c6";

const ADDR_2:&str="5Dw1dQV6zFopC52H4D3hw366WFb9DpueC91hA9KoJSuP4qqV";
const PUB_KEY_2:&str="529a53c953c69d2144d0a9515ece42f6de4a00fe0a68135a7c7423517c9d4902";
const SECRET_2:&str="1b7185e8a4082518b560f004ac2031f72b254d621fb318e99f9c6f27514e006a";

#[tokio::main]
async fn main() {
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::INFO)
        // completes the builder.
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    get_fee_info().await;
}

#[subxt::subxt(runtime_metadata_path = "artifacts/westmint.scale")]
mod polkadot {}

async fn generate_address(){
    let (pair,seed)= sp_core::sr25519::Pair::generate();
    let pub_key= pair.public().to_vec();

    println!("secret:{}", hex::encode( &seed.to_vec()));
    println!("public key :{}", hex::encode(pair.public().as_slice()));

    let account_id = sp_core::crypto::AccountId32::from_slice(pub_key.as_slice()).expect("convert to accountId error");

    println!("address :{}", account_id.to_ss58check());
}

async fn get_balance_test(){
    let api=ClientBuilder::new()
        .set_url("wss://westmint-rpc.polkadot.io:443")
        .build()
        .await.unwrap()
        .to_runtime_api::<polkadot::RuntimeApi<DefaultConfig, PolkadotExtrinsicParams<DefaultConfig>>>();

    let addr= sp_core::crypto::AccountId32::from_ss58check(ADDR_1).expect("addr convert error");
    let result = api
        .storage()
        .system()
        .account(&addr,None)
        .await
        .unwrap();
    println!("nonce:{}",result.nonce.to_string());
    println!("free:{}",result.data.free.to_string());
    println!("reserved:{}",result.data.reserved.to_string());
    println!("misc_frozen:{}",result.data.misc_frozen.to_string());
    println!("fee_frozen:{}",result.data.fee_frozen.to_string());
}

async fn transfer_test2(){
    let api=ClientBuilder::new()
        .set_url("wss://westmint-rpc.polkadot.io:443")
        .build()
        .await.unwrap()
        .to_runtime_api::<polkadot::RuntimeApi<DefaultConfig, SubstrateExtrinsicParams<DefaultConfig>>>();
    let from_secret= SECRET_1;
    let from_addr= sp_core::crypto::AccountId32::from_ss58check(ADDR_1).expect("addr convert error");
    let to_address= sp_core::crypto::AccountId32::from_ss58check(ADDR_2).expect("addr convert error");
    let amount= u128::from_str("1000000000000").expect("amount convert error");
    let signer= sp_core::sr25519::Pair::from_seed_slice(&hex::decode(from_secret).unwrap()).expect("sr25519 from seed error");

    // Configure the transaction tip and era:
    /*
    let _tx_params = SubstrateExtrinsicParamsBuilder::new()
        .tip(AssetTip::new(20_000_000_000))
        .era(Era::Immortal, *api.client.genesis());
    */

    let signer= subxt::PairSigner::<DefaultConfig,_>::new(signer);
    let tx_hash = api
        .tx()
        .balances()
        .transfer(subxt::sp_runtime::MultiAddress::Id(to_address), amount).expect("create transfer error")
        .create_signed(&signer, Default::default())
        .await.expect("commit error");
    println!("tx hash:{}",hex::encode(&tx_hash.encode()));
}

async fn transfer_test(){
    let api=ClientBuilder::new()
        .set_url("wss://westmint-rpc.polkadot.io:443")
        .build()
        .await.unwrap()
        .to_runtime_api::<polkadot::RuntimeApi<DefaultConfig, SubstrateExtrinsicParams<DefaultConfig>>>();

    let from_secret=SECRET_1;
    let from_addr= sp_core::crypto::AccountId32::from_ss58check(ADDR_1).expect("addr convert error");
    let result = api
        .storage()
        .system()
        .account(&from_addr,None)
        .await
        .unwrap();

    let to_address= sp_core::crypto::AccountId32::from_ss58check(ADDR_2).expect("addr convert error");
    let amount=u128::from_str("1000000000000").expect("amount convert error");
    let caller= polkadot::balances::calls::Transfer{
        dest:subxt::sp_runtime::MultiAddress::Id(to_address.clone()),
        value:amount
    };
    let nonce=result.nonce;
    println!("nonce:{}",nonce);
    let unsigned= convert_to_unsigned(nonce,caller,&api).await.expect("convert to unsigned error");
    println!("unsigned:{}",hex::encode(&unsigned));

    let signer= sp_core::sr25519::Pair::from_seed_slice(&hex::decode(from_secret).unwrap()).expect("sr25519 from seed error");
    let mut sign= signer.sign(&unsigned).0.to_vec();
    sign.insert(0,0x01u8); // 1代表 sr25519
    println!("sign result:{}",hex::encode(&sign));

    let caller = polkadot::balances::calls::Transfer{
        dest:subxt::sp_runtime::MultiAddress::Id(to_address.clone()),
        value:amount
    };

    let tx_hash=  commit_unsigned(nonce,&sp_runtime::MultiAddress::Id(from_addr.clone()),&sign, caller,&api).await.expect("commit error");
    println!("tx hash!!:{}",tx_hash);
}

async fn convert_to_unsigned<C: Call + Send + Sync>(nonce:u32,caller:C,api:&polkadot::RuntimeApi<DefaultConfig, SubstrateExtrinsicParams<DefaultConfig>>)->Result<Vec<u8>,subxt::BasicError>{
    // 2. SCALE encode call data to bytes (pallet u8, call u8, call params).
    let call_data = {
        let mut bytes = Vec::new();
        let metadata = api.client.metadata();
        let pallet = metadata.pallet(C::PALLET)?;
        bytes.push(pallet.index());
        bytes.push(pallet.call_index::<C>()?);
        caller.encode_to(&mut bytes);
        subxt::Encoded(bytes)
    };

    // 3. Construct our custom additional/extra params.
    let additional_and_extra_params = {
        // Obtain spec version and transaction version from the runtime version of the client.
        let runtime= api.client.rpc().runtime_version(None).await?;
        SubstrateExtrinsicParams::<DefaultConfig>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            api.client.genesis().clone(),
            Default::default(),
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

async fn commit_unsigned<C: Call + Send + Sync,Config:subxt::Config>(nonce:Config::Index,sender_address:&Config::Address,signature:&[u8],caller:C,api:&polkadot::RuntimeApi<Config, SubstrateExtrinsicParams<Config>>)->Result<String,subxt::BasicError>{
    // 2. SCALE encode call data to bytes (pallet u8, call u8, call params).
    let call_data = {
        let mut bytes = Vec::new();
        let metadata = api.client.metadata();
        let pallet = metadata.pallet(C::PALLET)?;
        bytes.push(pallet.index());
        bytes.push(pallet.call_index::<C>()?);
        caller.encode_to(&mut bytes);
        subxt::Encoded(bytes)
    };

    // 3. Construct our custom additional/extra params.
    let additional_and_extra_params = {
        // Obtain spec version and transaction version from the runtime version of the client.
        let runtime= api.client.rpc().runtime_version(None).await?;
        SubstrateExtrinsicParams::<Config>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            api.client.genesis().clone(),
            Default::default(),
        )
    };

    println!("xt signature: {}", hex::encode(signature));

    // 5. Encode extrinsic, now that we have the parts we need. This is compatible
    //    with the Encode impl for UncheckedExtrinsic (protocol version 4).
    let extrinsic = {
        let mut encoded_inner = Vec::new();
        // "is signed" + transaction protocol version (4)
        (0b10000000 + 4u8).encode_to(&mut encoded_inner);
        println!("extrinsic 1:{}",hex::encode(&encoded_inner));
        // from address for signature
        sender_address.encode_to(&mut encoded_inner);
        println!("extrinsic 2:{}",hex::encode(&encoded_inner));
        // the signature bytes
        Encoded(signature.to_vec()).encode_to(&mut encoded_inner);
        println!("extrinsic 3:{}",hex::encode(&encoded_inner));
        // attach custom extra params
        additional_and_extra_params.encode_extra_to(&mut encoded_inner);
        // and now, call data
        call_data.encode_to(&mut encoded_inner);
        // now, prefix byte length:
        let len = codec::Compact(
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
    let tx_hash = api.client.rpc().submit_extrinsic(Encoded(extrinsic)).await?;
    Ok(hex::encode(tx_hash.as_ref()))
    //println!("tx hash:{}",hex::encode(&Encoded(extrinsic).encode()));

    //Ok("".to_string())
}

async fn get_empty_extrinisc<C: Call + Send + Sync,Config:subxt::Config>(nonce:Config::Index,sender_address:&Config::Address,caller:C,api:&polkadot::RuntimeApi<Config, SubstrateExtrinsicParams<Config>>)->Result<Vec<u8>,subxt::BasicError>{
    // 2. SCALE encode call data to bytes (pallet u8, call u8, call params).
    let call_data = {
        let mut bytes = Vec::new();
        let metadata = api.client.metadata();
        let pallet = metadata.pallet(C::PALLET)?;
        bytes.push(pallet.index());
        bytes.push(pallet.call_index::<C>()?);
        caller.encode_to(&mut bytes);
        subxt::Encoded(bytes)
    };

    // 3. Construct our custom additional/extra params.
    let additional_and_extra_params = {
        // Obtain spec version and transaction version from the runtime version of the client.
        let runtime= api.client.rpc().runtime_version(None).await?;
        SubstrateExtrinsicParams::<Config>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            api.client.genesis().clone(),
            Default::default(),
        )
    };

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
        Encoded(signature.to_vec()).encode_to(&mut encoded_inner);
        println!("added signature:{}",hex::encode(&encoded_inner));
        // attach custom extra params
        additional_and_extra_params.encode_extra_to(&mut encoded_inner);
        // and now, call data
        call_data.encode_to(&mut encoded_inner);
        // now, prefix byte length:
        let len = codec::Compact(
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

async fn get_fee_info(){
    let api=ClientBuilder::new()
        .set_url("wss://westmint-rpc.polkadot.io:443")
        .build()
        .await.unwrap()
        .to_runtime_api::<polkadot::RuntimeApi<DefaultConfig, SubstrateExtrinsicParams<DefaultConfig>>>();

    let from_secret=SECRET_1;
    let from_addr= sp_core::crypto::AccountId32::from_ss58check(ADDR_1).expect("addr convert error");
    let result = api
        .storage()
        .system()
        .account(&from_addr,None)
        .await
        .unwrap();

    let to_address= sp_core::crypto::AccountId32::from_ss58check(ADDR_2).expect("addr convert error");
    let amount=u128::from_str("1000000000000").expect("amount convert error");
    let caller= polkadot::balances::calls::Transfer{
        dest:subxt::sp_runtime::MultiAddress::Id(to_address.clone()),
        value:amount
    };

    let from_addr=subxt::sp_runtime::MultiAddress::Id(from_addr);
    let extrinisc= get_empty_extrinisc(result.nonce,&from_addr,caller,&api).await.expect("get extrinisc error");
    let extrinisc:Bytes= extrinisc.into();

    let params=jsonrpsee::rpc_params!( extrinisc );

    match api.client.rpc().client
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