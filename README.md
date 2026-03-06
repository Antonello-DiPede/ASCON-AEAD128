# ASCON-AEAD128 Interactive Explorer

An interactive educational tool to learn and explore the **ASCON-AEAD128** authenticated encryption algorithm (NIST SP 800-232).

## Features

### 📖 Theory Tab
Step-by-step explanation of the full algorithm, written for complete beginners:
- Internal state structure (320 bits, 5 words, rate vs capacity)
- The permutation Ascon-p[r] — all 3 layers explained (Constant Addition, S-box, Linear Diffusion)
- All 4 encryption phases with exact formulas
- Optional features: Tag Truncation and Nonce Masking

### 🔬 Cipher Explorer Tab
Run a real ASCON-AEAD128 encryption and trace every single operation:
- Input your own **Key**, **Nonce**, **Associated Data** and **Plaintext** (hex)
- Step-by-step list of every state transformation, grouped by phase
- For each step: full 320-bit state display with changed words highlighted in orange
- **Drill into any permutation call** (p[8] or p[12]) — navigate round by round, sub-step by sub-step (Before → After Constant → After S-box → After Linear Diffusion)
- Two presets: **Load Example** and **KAT Count=1** (verifiable against official NIST test vectors)

## Usage
[Click Here](https://ascon-aead-128.vercel.app?_vercel_share=TfE7pLxA0KaBrOVepuRvrijOspptmQS)

## Notes

- All crypto is implemented in JavaScript using **BigInt** (64-bit words, little-endian)
- Results are correct and verifiable against the official KAT file:  
  `https://github.com/ascon/ascon-c/blob/main/crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt`