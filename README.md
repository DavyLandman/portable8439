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

- __chacha20__: a fresh implementation based on reading the RFC 8439.
    It supports little/big endianness, avoids unaligned reads if they are
    not possible and is fast even on older compilers (use `-O2` or `-O3`).
- __poly1305__: [floodberry's poly1305-donna](https://github.com/floodyberry/poly1305-donna)
    is quite hard to beat. It tries to guess the best math mode to use (32/64/128 bit)
    and appears to be quite portable. I've only changed the header logic to remove
    some warnings by the compiler.
- __rfc8439__: a fresh implementation based on RFC 8439 description. Primarily
    calling chacha20 & poly1305 code.

## Usage

The design of the API is quite straight forward, there is not incremental/streaming
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

## Installing

As package management in C is a bit of a mess we algamize releases into a single
c and h file. So always download the released versions, it is easy to include in
your project and also helps the c++ compiler do better optimization.

## License

The code is licensed under CC0 (a public domain like license) and contains code
from floodberry/poly1305 which is also under the public domain.