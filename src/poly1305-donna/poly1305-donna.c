#include "poly1305-donna.h"

/* auto detect between 32bit / 64bit */
#if /* uint128 available on 64bit system*/ \
	(defined(__SIZEOF_INT128__) && defined(__LP64__)) \
	/* MSVC 64bit compiler */ \
	|| (defined(_MSC_VER) && defined(_M_X64)) \
	/* gcc >= 4.4 64bit */ \
	|| (defined(__GNUC__) && defined(__LP64__) && \
		((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4)))) 
#	define __GUESS64
#else
#	define __GUESS32
#endif

#if defined(POLY1305_8BIT)
#	include "poly1305-donna-8.h"
#elif defined(POLY1305_16BIT)
#	include "poly1305-donna-16.h"
#elif defined(POLY1305_32BIT) || (!defined(POLY1305_64BIT) && defined(__GUESS32))
#	include "poly1305-donna-32.h"
#else
#	include "poly1305-donna-64.h"
#endif

void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	size_t i;

	/* handle leftover */
	if (st->leftover) {
		size_t want = (poly1305_block_size - st->leftover);
		if (want > bytes)
			want = bytes;
		for (i = 0; i < want; i++)
			st->buffer[st->leftover + i] = m[i];
		bytes -= want;
		m += want;
		st->leftover += want;
		if (st->leftover < poly1305_block_size)
			return;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
		st->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= poly1305_block_size) {
		size_t want = (bytes & ~(poly1305_block_size - 1));
		poly1305_blocks(st, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes) {
		for (i = 0; i < bytes; i++)
			st->buffer[st->leftover + i] = m[i];
		st->leftover += bytes;
	}
}

int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]) {
	size_t i;
	unsigned int dif = 0;
	for (i = 0; i < 16; i++)
		dif |= (mac1[i] ^ mac2[i]);
	dif = (dif - 1) >> ((sizeof(unsigned int) * 8) - 1);
	return (dif & 1);
}
