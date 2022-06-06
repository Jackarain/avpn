set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)
project(zstd C)

file(GLOB zstd_SRC
    "lib/common/pool.h"
    "lib/common/threading.h"
    "lib/common/xxhash.h"
    "lib/compress/zstdmt_compress.h"
    "lib/zdict.h"
    "lib/dictBuilder/cover.h"
    "lib/dictBuilder/divsufsort.h"
    "lib/common/fse.h"
    "lib/common/huf.h"
    "lib/zstd.h"
    "lib/common/zstd_internal.h"
    "lib/zstd_errors.h"
    "lib/compress/zstd_compress.h"
    "lib/compress/zstd_compress_literals.h"
    "lib/compress/zstd_compress_sequences.h"
    "lib/compress/zstd_cwksp.h"
    "lib/compress/zstd_compress_superblock.h"
    "lib/compress/zstd_fast.h"
    "lib/compress/zstd_double_fast.h"
    "lib/compress/zstd_lazy.h"
    "lib/compress/zstd_opt.h"
    "lib/compress/zstd_ldm.h"
    "lib/decompress/zstd_ddict.h"
    "lib/legacy/zstd_legacy.h"
    "lib/legacy/zstd_v01.h"
    "lib/legacy/zstd_v02.h"
    "lib/legacy/zstd_v03.h"
    "lib/legacy/zstd_v04.h"
    "lib/legacy/zstd_v05.h"
    "lib/legacy/zstd_v06.h"
    "lib/legacy/zstd_v07.h"

    "programs/benchzstd.h"
    "programs/datagen.h"
    "programs/dibio.h"
    "programs/fileio.h"
    "programs/platform.h"
    "programs/util.h"

    "lib/common/debug.c"
    "lib/common/entropy_common.c"
    "lib/common/error_private.c"
    "lib/common/pool.c"
    "lib/common/threading.c"
    "lib/common/xxhash.c"
    "lib/common/zstd_common.c"
    "lib/common/fse_decompress.c"
    "lib/compress/hist.c"
    "lib/compress/fse_compress.c"
    "lib/compress/huf_compress.c"
    "lib/compress/zstdmt_compress.c"
    "lib/compress/zstd_compress.c"
    "lib/compress/zstd_compress_literals.c"
    "lib/compress/zstd_compress_sequences.c"
    "lib/compress/zstd_compress_superblock.c"
    "lib/compress/zstd_fast.c"
    "lib/compress/zstd_double_fast.c"
    "lib/compress/zstd_lazy.c"
    "lib/compress/zstd_opt.c"
    "lib/compress/zstd_ldm.c"
    "lib/decompress/huf_decompress.c"
    "lib/decompress/zstd_decompress.c"
    "lib/decompress/zstd_decompress_block.c"
    "lib/decompress/zstd_ddict.c"
    "lib/dictBuilder/cover.c"
    "lib/dictBuilder/fastcover.c"
    "lib/dictBuilder/divsufsort.c"
    "lib/dictBuilder/zdict.c"
    "lib/legacy/zstd_v01.c"
    "lib/legacy/zstd_v02.c"
    "lib/legacy/zstd_v03.c"
    "lib/legacy/zstd_v04.c"
    "lib/legacy/zstd_v05.c"
    "lib/legacy/zstd_v06.c"
    "lib/legacy/zstd_v07.c"

    "programs/util.c"
    "programs/timefn.c"
    "programs/benchfn.c"
    "programs/benchzstd.c"
    "programs/datagen.c"
    "programs/dibio.c"
    "programs/fileio.c"
    "programs/zstdcli.c"
    "programs/zstdcli_trace.c"
)

if (CMAKE_COMPILER_IS_GNUCC AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" AND NOT WIN32)
    enable_language(ASM)
    list(APPEND zstd_SRC "lib/decompress/huf_decompress_amd64.S")
endif()

add_library(zstd STATIC ${zstd_SRC})

target_include_directories(zstd PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/lib
)

target_compile_definitions(zstd PUBLIC -DZSTD_MULTITHREAD=1 -DZSTD_LEGACY_SUPPORT=5)

set_target_properties(zstd PROPERTIES FOLDER "third_party")
set_target_properties(zstd PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(zstd PROPERTIES OUTPUT_NAME zstd PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)
