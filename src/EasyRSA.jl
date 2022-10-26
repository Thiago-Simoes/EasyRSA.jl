module EasyRSA

import Random
using Primes

export generate_p_q, generate_keys, encrypt, decrypt

struct RSAKey
    public::Bool
    key::BigInt
    n::BigInt
end


function extended_euclides(a::T, b::T)::Tuple{T, T, T} where T <: Union{Int64, BigInt}
    r, r1, u, v, u1, v1 = a, b, 1, 0, 0, 1

    while (r1 != 0)
        q = r ÷ r1
        rs, us, vs = r, u, v
        r, u, v = r1, u1, v1
        r1 = rs - q*r1
        u1 = us - q*u
        v1 = vs - q*v1
    end

    return (r, u, v)
end


function inv_mod(e::T, f::T)::T where T <: Union{Int64, BigInt}
    g, x, y = extended_euclides(e, f)
    if g != 1
        throw("Erro! Não há inverso modular")
    else
        return BigInt(x) % BigInt(f)
    end
end


function generate_p_q(B::Int64=512)::Tuple{BigInt, BigInt}
    if !(typeof(B) <: Integer)
        throw("B deve ser um inteiro!")
    end

    primes = []
    while length(primes) != 2
        tmp = _generate_prime(B)
        test = isprime(tmp)
        if test && !(tmp in primes)
            push!(primes, tmp)
        end
    end

    p = maximum(primes)
    q = minimum(primes)

    return (p, q)
end


function generate_e_d(p::T, q::T)::Tuple{T, T} where T <: Union{BigInt, Int64}
    totiente = (p-1)*(q-1)
    e = rand(Random.RandomDevice(), 1:totiente)
    while true
        e = rand(Random.RandomDevice(), 1:totiente)
        if(gcd(totiente, e)==1)
            break
        end
    end
    d = inv_mod(e, totiente)
    return (e, d)
end


function generate_keys(p::T, q::T)::Tuple{RSAKey, RSAKey} where T <: Union{BigInt, Int64}
    n::BigInt = p*q
    e::BigInt, d::BigInt = generate_e_d(p,q)
    return (RSAKey(true, e, n), RSAKey(false, d, n))
end


function modularMulti(m::Integer, e::Integer, n::Integer)::Union{BigInt, Int64}
    return powermod(m, e, BigInt(n))
end


function encrypt(m::String, k::RSAKey)::Union{BigInt, Vector{BigInt}}
    e, n = k.key, k.n

    if length(m) > 100
        m = _split_n(m, 100)
        msg = _parser_to_int.(m) 
        foo(x) = return modularMulti(x, e, n) 
        return foo.(msg)
    else
        msg = _parser_to_int(m)
        return modularMulti(msg, e, n)
    end
end


function decrypt(m::BigInt, k::RSAKey)::String
    d, n = k.key, k.n
    decrypted = modularMulti(m,d,n)
    return _parser_from_int(decrypted)
end


function decrypt(m::Vector{BigInt}, k::RSAKey)::String
    d, n = k.key, k.n
    decrypted = []
    for msg in m
        push!(decrypted, _parser_from_int(modularMulti(msg,d,n)))
    end
    return string(decrypted...)
end


# Auxiliary functions


_bits_size(x::Integer)::Integer = floor(log2(x))+1


function _generate_prime(bits::Integer)
    function _near_prime(x::Integer)::Integer
        return rand(Random.RandomDevice(), false:true) ? nextprime(x) : prevprime(x)
    end
    ret = nothing
    random_number = _randbits(bits)
    while (ret == nothing)
        tmp = _near_prime(random_number)
        if _bits_size(tmp) == bits && isprime(tmp)
            ret = tmp
        end
    end
    return ret
end


function _parser_from_int(m::Union{BigInt, Int64})::String
    msg::String = string(m)
    if length(msg) % 3 !== 0
        msg = "0"^(3-(length(string(m)) % 3))*msg
    end
    splited_msg::Vector{String} = _split_n(msg, 3)
    parse_int(x::String)::Int64 = return parse(Int64, x)
    ret = String(UInt8.(parse_int.(splited_msg)))
    return ret    
end


function _parser_to_int(m::String)::BigInt
    @assert (length(m) > 1)
    ret = ""
    for i in 1:(length(m))
        ret *= string(Int(m[i]), base=10, pad=3)
    end
    return parse(BigInt, ret)
end


function _randbits(n::Int64)::BigInt
    range = 2^BigInt(n-1):2^BigInt(n)-1
    return rand(Random.RandomDevice(), range)
end


function _split_n(s::Union{String, Int64}, n::Int64)::Vector
    ret = []
    for i in 1:n:length(s)  
        final_indx = min((i+n-1), length(s)) 
        push!(ret, s[i:final_indx])
    end
    return ret
end

end # module EasyRSA
