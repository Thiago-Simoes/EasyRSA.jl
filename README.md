# EasyRSA.jl

This project **should not** be used in production environments under any circumstances.

This project is under development and totally free-to-use, feel free to contribute. I'm a student so forgive any possible problem and report it opening a issue. Ideas can also, and should, be sent.

## Technical reference

This project use as reference the original paper of RSA ("A Method for Obtaining Digital Signatures and Public-Key Cryptosystems").

# How to install

Just copy and paste the following command in Julia Terminal:
```julia
import Pkg; Pkg.add(url="https://github.com/Thiago-Simoes/EasyRSA.jl")
```

# How to use

### Generating keys

1. Choose how many bits do you want for your keys.
```julia
bits = 512
```
2. Generate your P and Q:
```julia
p, q = generate_p_q(bits)
```
3. Generate your keys:
> This returns a Tuple, respectively Public and Private Key.
```julia
keys = generate_keys(p, q)
```

### Encrypting

1. Use your Public Key to encrypt your data.
```julia
msg = "Secret message."
encrypted_message = encrypt(msg, keys[1])
```

### Decrypting

1. Use your Private Key to decrypt your data.
```julia
decrypted_message = decrypt(encrypted_message, keys[2])
```
