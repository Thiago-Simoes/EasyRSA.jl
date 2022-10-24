using Test
using RSA

p, q = generate_p_q(512)
keys = generate_keys(p,q)
msg = "Test message."
encrypted = encrypt(msg, keys[1])
decrypted = decrypt(encrypted, keys[2])

@test msg == decrypted