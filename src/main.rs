use ark_bls12_381::Bls12_381;
use ark_crypto_primitives::CRH;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use dialoguer::{theme::ColorfulTheme, Select};
use zkmember::member::Member;

// Conditional imports for pedersen modules
#[cfg(feature = "pedersen761")]
use zkmember::pedersen761::{
    common::{
        new_membership_tree, LeafHash, Pedersen761Field as PedersenField, Root, TwoToOneHash,
    },
    constraint::MerkleTreeCircuit,
};

#[cfg(feature = "pedersen381")]
use zkmember::pedersen381::{
    common::{
        new_membership_tree, LeafHash, Pedersen381Field as PedersenField, Root, TwoToOneHash,
    },
    constraint::MerkleTreeCircuit,
};

// Conditional curve import/alias
#[cfg(feature = "pedersen761")]
use ark_bw6_761::BW6_761;
#[cfg(feature = "pedersen761")]
type Curve = BW6_761;

#[cfg(feature = "pedersen381")]
use ark_bls12_381::Bls12_381;
#[cfg(feature = "pedersen381")]
type Curve = Bls12_381;

fn main() {
    let mut members: Box<Vec<Member>> = Box::new(Vec::<Member>::new());
    let mut _last_circuit: Option<MerkleTreeCircuit>;

    let mut rng = ark_std::test_rng();

    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as CRH>::setup(&mut rng).unwrap();

    // public store
    let mut root: Option<Root>;

    loop {
        let options = &[
            "Register a new member",
            "Generate a proof for a member",
            "Verify proof",
            "Exit",
        ];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option")
            .default(0)
            .items(&options[..])
            .interact()
            .unwrap();

        match selection {
            0 => {
                /* Register member */
                let id = dialoguer::Input::<String>::new()
                    .with_prompt("Enter ID")
                    .allow_empty(false)
                    .interact_text()
                    .unwrap();
                let email = dialoguer::Input::<String>::new()
                    .with_prompt("Enter Email")
                    .allow_empty(false)
                    .interact_text()
                    .unwrap();
                members.push(Member::new(id.into(), email.into(), None));
                println!("\x1b[0;32mNumber of Members: {}\x1b[0m", members.len());

                let mut leaves = members
                    .iter()
                    .map(|member| member.hash::<LeafHash>(&leaf_crh_params))
                    .collect::<Vec<_>>();
                let tree =
                    new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);

                root = Some(tree.root());

                let mut root_serialization = Vec::new();
                root.serialize(&mut root_serialization).unwrap();
                println!("\x1b[0;33mroot: {}\x1b[0m", hex::encode(root_serialization));
            }

            1 => {
                /* Generate Proof */
                let id = dialoguer::Input::<String>::new()
                    .with_prompt("Enter ID")
                    .interact_text()
                    .unwrap();

                if let Some(index) = members.iter().position(|member| member.id == id) {
                    let mut leaves = members
                        .iter()
                        .map(|member| member.hash::<LeafHash>(&leaf_crh_params))
                        .collect::<Vec<_>>();
                    let tree =
                        new_membership_tree(&leaf_crh_params, &two_to_one_crh_params, &mut leaves);

                    let root = tree.root();
                    let path = tree.generate_proof(index).unwrap();
                    let member = members.get(index).unwrap();

                    let circuit = MerkleTreeCircuit {
                        leaf_crh_params: &leaf_crh_params,
                        two_to_one_crh_params: &two_to_one_crh_params,
                        root,
                        leaf_hash: member.hash::<LeafHash>(&leaf_crh_params),
                        authentication_path: Some(path),
                    };

                    let (pk, vk) =
                        Groth16::<Curve>::circuit_specific_setup(circuit.clone(), &mut rng)
                            .unwrap();
                    let proof = Groth16::<Curve>::prove(&pk, circuit, &mut rng).unwrap();

                    let mut leaf_hash_serialization = Vec::new();
                    member
                        .hash::<LeafHash>(&leaf_crh_params)
                        .serialize(&mut leaf_hash_serialization)
                        .unwrap();
                    println!(
                        "\x1b[0;32mLeaf hash: {}\x1b[0m",
                        hex::encode(&leaf_hash_serialization)
                    );

                    let mut root_serialization = Vec::new();
                    root.serialize(&mut root_serialization).unwrap();
                    println!(
                        "\x1b[0;33mRoot: {}\x1b[0m",
                        hex::encode(&root_serialization)
                    );

                    let mut proof_serialization = Vec::new();
                    proof.serialize(&mut proof_serialization).unwrap();
                    println!(
                        "\x1b[0;33mGenerated proof: {}\x1b[0m",
                        hex::encode(&proof_serialization)
                    );

                    let mut vk_serialization = Vec::new();
                    vk.serialize(&mut vk_serialization).unwrap();
                    println!(
                        "\x1b[0;90mVerification key: {}\x1b[0m",
                        hex::encode(&vk_serialization)
                    );

                    // Construct public input vector properly
                    let public_input = vec![root, member.hash::<LeafHash>(&leaf_crh_params)];

                    // Verify the proof with proper error handling
                    match Groth16::<Curve>::verify(&vk, &public_input, &proof) {
                        Ok(true) => println!("\x1b[0;32mProof verified successfully!\x1b[0m"),
                        Ok(false) => println!("\x1b[0;31mProof verification failed\x1b[0m"),
                        Err(e) => println!("\x1b[0;31mVerification error: {:?}\x1b[0m", e),
                    }
                } else {
                    println!("\x1b[0;31mMember not found\x1b[0m");
                }
            }

            2 => {
                /* Verify proof */
                let root_hex = dialoguer::Input::<String>::new()
                    .with_prompt("Enter root (hex encoded)")
                    .interact_text()
                    .unwrap();
                let leaf_hash_hex = dialoguer::Input::<String>::new()
                    .with_prompt("Enter leaf hash (hex encoded)")
                    .interact_text()
                    .unwrap();
                let proof_hex = dialoguer::Input::<String>::new()
                    .with_prompt("Enter proof (hex encoded)")
                    .interact_text()
                    .unwrap();
                let vk_hex = dialoguer::Input::<String>::new()
                    .with_prompt("Enter verification key (hex encoded)")
                    .interact_text()
                    .unwrap();

                // Deserialize inputs
                let root: Root = Root::deserialize(&*hex::decode(root_hex).unwrap()).unwrap();
                let leaf_hash: PedersenField =
                    PedersenField::deserialize(&*hex::decode(leaf_hash_hex).unwrap()).unwrap();
                let public_inputs = vec![root, leaf_hash];

                let proof = Proof::deserialize(&*hex::decode(proof_hex).unwrap()).unwrap();

                let vk =
                    VerifyingKey::<Curve>::deserialize(&*hex::decode(vk_hex).unwrap()).unwrap();

                // Verify the proof with proper error handling
                match Groth16::<Curve>::verify(&vk, &public_inputs, &proof) {
                    Ok(true) => println!("\x1b[0;32mProof verified successfully!\x1b[0m"),
                    Ok(false) => println!("\x1b[0;31mProof verification failed\x1b[0m"),
                    Err(e) => println!("\x1b[0;31mVerification error: {:?}\x1b[0m", e),
                }
            }

            3 => std::process::exit(0),

            _ => unreachable!(),
        }
        println!()
    }
}
