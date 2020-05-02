#!/bin/bash
set -e -o nounset

DST_DIR="$1"
VERSION="$2"

mkdir -p "$DST_DIR"

SRC_DIR="src/"

PORTABLE_FILES=(portable8439 portable_wipe)


DST_HEADER="$DST_DIR/portable8439.h"
DST_SOURCE="$DST_DIR/portable8439.c"


function remove_header_guard() {
    # we reverse lines so that it is easier to detect the last endif to drop
    tac | \
        awk '
        BEGIN{LAST_END_FOUND=0;} 
        /#endif/ && !LAST_END_FOUND { LAST_END_FOUND=1; next; } 
        /#.*_H*$/ { next; }
        42
        ' | \
        tac
}

function remove_local_imports() {
    sed 's/#include ".*h"//'
}

function remove_double_blank_lines() {
    cat -s
}

function make_everything_static() {
    sed \
        -e $'s/^\([^\ \t\#{}()\/]\)/static \\1/' \
        -e 's/static static/static/' \
        -e 's/static struct/struct/' \
        -e 's/static typedef/typedef/' \
        -e 's/static extern/extern/' \
        -e 's/static const/const/'
}

function add_decl_spec() {
    sed \
        -e 's/^static /static PORTABLE_8439_DECL /' \
        -e $'s/^\([^\ \t#{}()\/*]\)/PORTABLE_8439_DECL \\1/' \
        -e 's/^PORTABLE_8439_DECL static/static/' \
        -e 's/^PORTABLE_8439_DECL typedef/typedef/'
}

echo "// portable8439 $VERSION
// Source: https://github.com/DavyLandman/portable8439
// Licensed under CC0-1.0
// Contains poly1305-donna (TODO: add specific version tag)

#ifndef __PORTABLE_8439_H
#define __PORTABLE_8439_H
#if defined(__cplusplus)
extern \"C\" {
#endif

// provide your own decl specificier like "-DPORTABLE_8439_DECL=ICACHE_RAM_ATTR"
#ifndef PORTABLE_8439_DECL
#define PORTABLE_8439_DECL
#endif
" > "$DST_HEADER"

for h in "${PORTABLE_FILES[@]}"; do 
    cat "$SRC_DIR/$h.h" | remove_header_guard 
done  | remove_double_blank_lines | add_decl_spec >> "$DST_HEADER" 

echo "#if defined(__cplusplus)
}
#endif
#endif" >> "$DST_HEADER"


echo "// portable8439 $VERSION
// Source: https://github.com/DavyLandman/portable8439
// Licensed under CC0-1.0
// Contains poly1305-donna (TODO: add specific version tag)

#include \"portable8439.h\"
" > "$DST_SOURCE"

for h in "chacha-portable/chacha-portable" "poly1305-donna/poly1305-donna"; do 
    echo "// ******* BEGIN: $h.h ********"
    cat "$SRC_DIR/$h.h" | remove_header_guard | \
        remove_local_imports | remove_double_blank_lines | \
        make_everything_static | add_decl_spec
    echo "// ******* END:   $h.h ********"
done >> "$DST_SOURCE"

function inline_src() {
    remove_local_imports | \
    remove_double_blank_lines | \
    make_everything_static # | \
    #add_decl_spec
}

echo "// ******* BEGIN: chacha-portable.c ********" >> "$DST_SOURCE"
inline_src <"$SRC_DIR/chacha-portable/chacha-portable.c" >> "$DST_SOURCE"
echo "// ******* END: chacha-portable.c ********" >> "$DST_SOURCE"


DONNA_ROOT="$SRC_DIR/poly1305-donna"
function merge_donna_src() {
    awk '
    /#.*include "poly1305-donna-[0-9]+.h"/ { system("cat src/poly1305-donna/"$3); next; }
    42
    ' "$DONNA_ROOT/poly1305-donna.c"
}

echo "// ******* BEGIN: poly1305-donna.c ********" >> "$DST_SOURCE"
merge_donna_src | inline_src >> "$DST_SOURCE"
echo "// ******* END: poly1305-donna.c ********" >> "$DST_SOURCE"


for h in "${PORTABLE_FILES[@]}"; do 
    echo "// ******* BEGIN: $h.c ********"
    cat "$SRC_DIR/$h.c" | remove_local_imports | \
    remove_double_blank_lines | add_decl_spec
    echo "// ******* END:   $h.c ********"
done >> "$DST_SOURCE"