# Portable 8439: ChaCha20-Poly1305 (RFC 8439) in portable & fast C99

## Introduction

A portable implementation of [RFC 8439](https://tools.ietf.org/html/rfc8439).
RFC 8439 deprecated RFC 7539: it contained a few clarifications and also
enforced the layout of the cipher stream (to append the tag to the end instead
of two separate fields)

ChaCha20-Poly1305 is a modern cryptographic construction to encrypt messages once
you have a shared (or session) key. [ChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant)
is a stream cipher and [Poly1305](https://en.wikipedia.org/wiki/Poly1305)
provides authentication. The ChaCha20-Poly1305 construction described in RFC 8349
add associated data to the mix, to help protocol designers merge in some extra
state to avoid replay attacks.

## This library

### Background

I made this library since no other C library offered the following characteristics:

- Support big-endian architectures
- Support architectures that do not allow unaligned loads
- C99 compliant
- High performance
- No external dependencies
- Readable code
- Implement latest version of chacha20 (96-bit nonce & 32bit counter)

Especially the first 3 points were hard to find together. Most libraries either
supported big-endianness but were slower (depending on the compiler)
even on little-endian machines. Similarly other libraries would assume you could
cast a u8 pointer to u32 pointer without problems (it's both an unaligned read
problem and undefined C behavior). The closest one was
[insane codings' simple c99](http://insanecoding.blogspot.com/2014/06/avoid-incorrect-chacha20-implementations.html)
implementation. Except that it still had the old style 64bit nonce & 64bit counter
and it required a modern compiler to make it fast on little-endian.

### Implementation

- __chacha20__: a fresh implementation based on the description in RFC 8439.
    It supports little/big endianness, avoids unaligned reads if they are
    not possible and is fast even on older compilers (use `-O2` or `-O3`).
- __poly1305__: [floodberry's poly1305-donna](https://github.com/floodyberry/poly1305-donna)
    is quite hard to beat. It tries to guess the best math mode to use (32/64/128 bit)
    and appears to be quite portable. I've only changed the header logic to remove
    some warnings by the compiler.
- __rfc8439__: a fresh implementation based on RFC 8439 description. Primarily
    calling chacha20 & poly1305 code.

## Usage

The design of the API is quite straight forward, there is no incremental/streaming
support since that makes it much easier to mess up.

- `portable_chacha20_poly1305_encrypt` takes plain text buffer (plus optional
    additional data) and encrypts it into a cipher text buffer.
    The pointers should not overlap, and the cipher text should have room for
    the original plain text size + `RFC_8439_TAG_SIZE`.
- `portable_chacha20_poly1305_decrypt` takes a cipher text (plus additional data)
    and decrypts it (if the data is not tampered with) into the plain text buffer.
    The pointers should not overlap, and the plain text buffer should have room
    for cipher text size - `RFC_8439_TAG_SIZE`.
    The function returns the size written to the plain text buffer, less than zero
    marks an decryption failure.

Please make sure to study the original [RFC](https://tools.ietf.org/html/rfc8439)
how to take care of your additional data, key, and nonce.
_Rough_ summary: never use the same pair of key & nonce. Random nonce is fine but
you have to make sure it is unique for the key. An incrementing nonce is also fine.
If you can pick additional data based on something that chances the semantics of
your protocol or something you already know about each other.

### Configuring unknown platforms

Portable 8439 is faster if it knows the platform is little endian and if the
biggest integer supported by the compiler is also the fastest.

If you are on a platform that is not included in the `__HAVE_LITTLE_ENDIAN`
detection, you should supply `-D__HAVE_LITTLE_ENDIAN` to your compiler.

If you are on a platform where the biggest math operations of the compiler are 
not the quickest, try measuring the effect of changing the version of the poly1305
implementation.

* `-DPOLY1305_8BIT`, 8->16 bit multiplies, 32 bit additions
* `-DPOLY1305_16BIT`, 16->32 bit multiples, 32 bit additions
* `-DPOLY1305_32BIT`, 32->64 bit multiplies, 64 bit additions
* `-DPOLY1305_64BIT`, 64->128 bit multiplies, 128 bit additions

(quote from the poly1305-donna readme)

## Installing

As package management in C is a bit of a mess we amalgamate the source code into a single
c and h file. Always download the [released versions](https://github.com/DavyLandman/portable8439/releases), they are easy to include in
your project and also helps the compiler optimize code.

## License

The code is licensed under [CC0](https://creativecommons.org/publicdomain/zero/1.0/) and contains code
from floodberry/poly1305-donna which is also under the public domain.