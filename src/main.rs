use anyhow::Result;

/// Performs a XOR operation between two encrypted cyphers with the same key. If one of the keys is longer than the other, it gets truncated.
/// The result is the msg_1[0..n] XOR msg_2[0..n] where n is the smaller length between the two.
fn combine_ciphers_remove_encryption_key(c1: &Vec<u8>, c2: &Vec<u8>) -> Vec<u8> {
    let common_key_length_used = c1.len().min(c2.len());

    let mut result = Vec::with_capacity(common_key_length_used);

    for i in 0..common_key_length_used {
        result.push(c1[i] ^ c2[i]);
    }

    result
}

/// Identify potential whitespaces in a combined cipher
fn identify_non_whitespaces_indexes(combi_cipher: Vec<u8>) -> Vec<usize> {
    combi_cipher
        .iter()
        .enumerate()
        .filter_map(|(i, c)| if *c < 65 { Some(i) } else { None })
        .collect()
}

fn main() -> Result<()> {
    let mut ciphers = [
        hex::decode("160111433b00035f536110435a380402561240555c526e1c0e431300091e4f04451d1d490d1c49010d000a0a4510111100000d434202081f0755034f13031600030d0204040e")?,
        hex::decode("050602061d07035f4e3553501400004c1e4f1f01451359540c5804110c1c47560a1415491b06454f0e45040816431b144f0f4900450d1501094c1b16550f0b4e151e03031b450b4e020c1a124f020a0a4d09071f16003a0e5011114501494e16551049021011114c291236520108541801174b03411e1d124554284e141a0a1804045241190d543c00075453020a044e134f540a174f1d080444084e01491a090b0a1b4103570740")?,
        hex::decode("000000000000001a49320017071704185941034504524b1b1d40500a0352441f021b0708034e4d0008451c40450101064f071d1000100201015003061b0b444c00020b1a16470a4e051a4e114f1f410e08040554154f064f410c1c00180c0010000b0f5216060605165515520e09560e00064514411304094c1d0c411507001a1b45064f570b11480d001d4c134f060047541b185c")?,
        hex::decode("0b07540c1d0d0b4800354f501d131309594150010011481a1b5f11090c0845124516121d0e0c411c030c45150a16541c0a0b0d43540c411b0956124f0609075513051816590026004c061c014502410d024506150545541c450110521a111758001d0607450d11091d00121d4f0541190b45491e02171a0d49020a534f")?,
        hex::decode("031a5410000a075f5438001210110a011c5350080a0048540e431445081d521345111c041f0245174a0006040002001b01094914490f0d53014e570214021d00160d151c57420a0d03040b4550020e1e1f001d071a56110359420041000c0b06000507164506151f104514521b02000b0145411e05521c1852100a52411a0054180a1e49140c54071d5511560201491b0944111a011b14090c0e41")?,
        hex::decode("0b4916060808001a542e0002101309050345500b00050d04005e030c071b4c1f111b161a4f01500a08490b0b451604520d0b1d1445060f531c48124f1305014c051f4c001100262d38490f0b4450061800004e001b451b1d594e45411d014e004801491b0b0602050d41041e0a4d53000d0c411c41111c184e130a0015014f03000c1148571d1c011c55034f12030d4e0b45150c5c")?,
        hex::decode("011b0d131b060d4f5233451e161b001f59411c090a0548104f431f0b48115505111d17000e02000a1e430d0d0b04115e4f190017480c14074855040a071f4448001a050110001b014c1a07024e5014094d0a1c541052110e54074541100601014e101a5c")?,
        hex::decode("0c06004316061b48002a4509065e45221654501c0a075f540c42190b165c")?,
        // Additional encryption
        // hex::decode("1f3cb1f3e01f3fd1f3ea1f3e61f3e01f3e71f3b31f3a91f3c81f3a91f3f91f3fc1f3fb1f3ec1f3e51f3f01f3a91f3f91f3ec1f3ec526e1b014a020411074c17111b1c071c4e4f0146430d0d08131d1d010707040017091648461e1d0618444f074c010e19594f0f1f1a07024e1d041719164e1c1652114f411645541b004e244f080213010c004c3b4c0911040e480e070b00310213101c4d0d4e00360b4f151a005253184913040e115454084f010f114554111d1a550f0d520401461f3e01f3e71f3e81f3e71f3ea1f3e01f3e81f3e51f3a91f3e01f3e71f3fa1f3fd1f3e01f3fd1f3fc1f3fd1f3e01f3e61f3e71f3a7")?,
        // This message has only characters from the encrypted key)
        hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")?
    ];
    ciphers.sort_by(|a, b| b.len().cmp(&a.len()));

    let mut messages = ciphers
        .iter()
        .map(|c| vec![0u8; c.len()])
        .collect::<Vec<Vec<u8>>>();

    let known_key_length = match ciphers.first() {
        Some(x) => x.len(),
        _ => 0,
    };
    let mut key = vec![0u8; known_key_length];

    for (i, c) in ciphers.iter().enumerate() {
        let other_ciphers: Vec<Vec<u8>> = ciphers
            .clone()
            .into_iter()
            .enumerate()
            .filter_map(|(index, item)| if index != i { Some(item) } else { None })
            .collect();

        let whitespaces_length = match other_ciphers.first() {
            Some(x) => x.len().min(c.len()),
            _ => 0,
        };
        let mut maybe_whitespaces = vec![true; whitespaces_length];

        for other in other_ciphers.iter() {
            // Combine each cipher with the others and identify whitespace values
            let combi_cipher = combine_ciphers_remove_encryption_key(c, other);
            let non_whitespace_indexes = identify_non_whitespaces_indexes(combi_cipher);
            // verify the whitespace locations among the different ciphers for each message
            for i in non_whitespace_indexes {
                maybe_whitespaces[i] = false;
            }
        }

        let whitespaces = maybe_whitespaces
            .iter()
            .enumerate()
            .filter_map(|(i, v)| if *v { Some(i) } else { None })
            .collect::<Vec<_>>();

        // Now that we guessed the whitespace characters:
        for index in whitespaces.iter() {
            // reveal the key character
            let key_char = c[*index] ^ 65;
            key[*index] = key_char;
            // Reveal the message characters
            for (msg_index, other) in other_ciphers.iter().enumerate() {
                let combi_cipher = combine_ciphers_remove_encryption_key(c, other);
                if *index < combi_cipher.len() {
                    let msg_char = combi_cipher[*index] ^ 65;
                    messages[msg_index][*index] = msg_char;
                }
            }
        }
    }

    println!("Cracked Encryption key {:?}", key);
    for (i, m) in messages.iter().enumerate() {
        println!("Cracked message ({}) :  {:?}", i, m);
    }

    Ok(())
}

#[test]
fn test_combination() {
    let c1 = vec![1, 1, 1, 1, 1];
    let c2 = vec![2, 2, 2, 2, 2];

    assert_eq!(
        vec![3, 3, 3, 3, 3],
        combine_ciphers_remove_encryption_key(&c1, &c2)
    );
}
