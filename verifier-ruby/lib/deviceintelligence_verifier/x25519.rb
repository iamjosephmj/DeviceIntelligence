# frozen_string_literal: true

module DeviceIntelligenceVerifier
  # Pure-Ruby X25519 (RFC 7748) — carried because the host's OpenSSL binding
  # does not expose OpenSSL::PKey::X25519, and the v2 envelope cannot work
  # without it. Montgomery ladder over GF(2^255-19), exactly the RFC's
  # reference construction; validated by the RFC 7748 known-answer tests.
  module X25519
    P = (1 << 255) - 19
    A24 = 121_665
    BASEPOINT = [0x09].pack("C*").ljust(32, "\x00") # u = 9, little-endian

    module_function

    # RFC 7748 X25519(k, u): 32-byte scalar, 32-byte little-endian u.
    def shared_secret(scalar, u)
      k = scalar.bytes
      raise ArgumentError, "scalar must be 32 bytes" if k.size != 32
      k[0] &= 248
      k[31] &= 127
      k[31] |= 64

      x1 = decode_u(u)
      x2 = 1
      z2 = 0
      x3 = x1
      z3 = 1
      swap = 0

      254.downto(0) do |t|
        kt = (k[t / 8] >> (t & 7)) & 1
        swap ^= kt
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = kt

        a  = fadd(x2, z2)
        aa = fmul(a, a)
        b  = fsub(x2, z2)
        bb = fmul(b, b)
        e  = fsub(aa, bb)
        c  = fadd(x3, z3)
        d  = fsub(x3, z3)
        da = fmul(d, a)
        cb = fmul(c, b)
        x3 = fsqr(fadd(da, cb))
        z3 = fmul(x1, fsqr(fsub(da, cb)))
        x2 = fmul(aa, bb)
        z2 = fmul(e, fadd(aa, fmul(A24, e)))
      end
      cswap(swap, x2, x3)
      cswap(swap, z2, z3)

      encode_u(fmul(x2, finv(z2)))
    end

    # The public key for a 32-byte scalar (the basepoint multiply).
    def public_from_private(scalar)
      shared_secret(scalar, BASEPOINT)
    end

    def decode_u(bytes)
      u = bytes.bytes.reverse.inject(0) { |acc, b| (acc << 8) | b }
      u & ((1 << 255) - 1) # RFC 7748: mask the high bit of the final byte
    end

    def encode_u(n)
      bytes = []
      32.times { bytes << (n & 0xFF); n >>= 8 }
      bytes.pack("C*") # 255 bits -> 32 little-endian bytes
    end

    def cswap(swap, a, b)
      dummy = swap * (a ^ b) # swap is 0 or 1 — exact conditional exchange
      [a ^ dummy, b ^ dummy]
    end

    def fadd(a, b)
      (a + b) % P
    end

    def fsub(a, b)
      (a - b) % P
    end

    def fmul(a, b)
      (a * b) % P
    end

    def fsqr(a)
      (a * a) % P
    end

    # z^(p-2) mod p — Fermat inversion.
    def finv(z)
      fexp(z, P - 2)
    end

    def fexp(base, exp)
      result = 1
      base = base % P
      while exp.positive?
        result = fmul(result, base) if exp.odd?
        base = fsqr(base)
        exp >>= 1
      end
      result
    end
  end
end
