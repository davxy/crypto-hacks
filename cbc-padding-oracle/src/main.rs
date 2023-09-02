//! Padding oracle attack PoC for AES-CBC.

use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes128,
};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

const BLKSIZ: usize = 16;

// This is our oracle.
//
// Should be a function of a component aware of the key and such that leaks some sort
// of information when the padding is not correct.
//
// In this case we return false when padding is not correct.
fn oracle(iv: Vec<u8>, mut ct: Vec<u8>) -> bool {
    let key = [0x42; 16];
    match Aes128CbcDec::new(key.as_slice().into(), iv.as_slice().into())
        .decrypt_padded_mut::<Pkcs7>(&mut ct)
    {
        Ok(_) => {
            //println!("Decrypt: {}", hex::encode(ct));
            true
        }
        Err(_) => false,
    }
}

// The attacker knows the initialization vector and the ciphertext.
//
// Will query the oracle which leaks padding errors information allowing
// incremental decryption of the message.
fn attack(iv: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let nblocks = ciphertext.len() / BLKSIZ;
    let mut plaintext = vec![0; ciphertext.len()];
    let mut dcurr: [u8; BLKSIZ] = [0; BLKSIZ];

    let mut prev = iv;

    for i in 0..nblocks {
        let curr = &ciphertext[i * BLKSIZ..(i + 1) * BLKSIZ];
        let curr_plain = &mut plaintext[i * BLKSIZ..(i + 1) * BLKSIZ];

        let curr = curr.to_vec();

        println!(
            "Block #{i}\n curr: {}\n prev: {}",
            hex::encode(&curr),
            hex::encode(&prev)
        );

        for pad in 1..=BLKSIZ {
            let prev_val = prev[BLKSIZ - pad];
            for i in 0..=255 {
                // prev' is computed
                prev[BLKSIZ - pad] = i;
                if oracle(prev.clone(), curr.clone()) {
                    // The decryption is successful if we accidentally obtained a correctly padded block.
                    // Valid pkcs #7 paddings are: [ ... 01 ], [ ... 02 02 ], [ ... 03 03 03 ], ...
                    // For pad=1 we want to double check that the block effectivelly decrypts to [... 01]
                    // and not to one of the other forms.
                    // For pad>1 this check is not necessary since the tail bytes are setted by us,
                    // thus there is no space for ambiguity.
                    if pad == 1 {
                        // Invert the first bit of the byte before and repeat the check.
                        // If we are in the case [... 01] then should be successful again.
                        let mut tmp = prev.clone();
                        tmp[BLKSIZ - (pad + 1)] ^= 1;
                        if !oracle(tmp, curr.clone()) {
                            println!("~ Ignoring decryption for block: {}", hex::encode(&prev));
                            continue;
                        }
                    }
                    break;
                }
            }

            // pad = prev' ^ decrypt(curr) => decrypt(curr) = prev' ^ pad
            let dc = prev[BLKSIZ - pad] ^ pad as u8;
            dcurr[BLKSIZ - pad] = dc;

            // plain = prev ^ decrypt(curr)
            let pc = prev_val ^ dc;
            curr_plain[BLKSIZ - pad] = pc;

            // update the prev block tail to be decryted to the next pad values.
            // For example. If we want the i-th value of curr to decrypt to 0x03 then
            // we set: prev[i] = dcurr[i] ^ 0x03
            for i in 1..=pad {
                prev[BLKSIZ - i] = dcurr[BLKSIZ - i] ^ (pad + 1) as u8;
            }
        }

        prev = curr;
    }

    // finally strip the real padding
    let pad = *plaintext.last().unwrap();
    plaintext.truncate(plaintext.len() - pad as usize);

    plaintext
}

fn main() {
    let key = [0x42; 16];
    let iv = [0x24; 16];
    let plaintext = b"hello world! this is my plaintext!!!";
    let plaintext_len = plaintext.len();

    // Buffer big enough for padded plaintext
    let mut buf = [0u8; BLKSIZ * 123];
    buf[..plaintext_len].copy_from_slice(plaintext);

    let ciphertext = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
        .unwrap();
    println!("CT: {}", hex::encode(&ciphertext));

    // Recover the plaintext
    let recovered = attack(iv.to_vec(), ciphertext.to_vec());
    println!("PT: {}", hex::encode(&plaintext));

    assert_eq!(plaintext, recovered.as_slice());
}
