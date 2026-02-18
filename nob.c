#define NOB_IMPLEMENTATION
#include "nob.h"

int main(int argc, char **argv) {
  NOB_GO_REBUILD_URSELF(argc, argv);

  Nob_Cmd cmd = {0};

  const char *output_name = "sendtoy";
  if (!nob_mkdir_if_not_exists("build"))
    return 1;

#ifdef _MSC_VER
  // MSVC Compiler
  nob_cmd_append(&cmd, "cl.exe");
  nob_cmd_append(&cmd, "/W4", "/Zi", "/wd4100", "/wd4996", "/nologo",
                 "/std:c11");
  nob_cmd_append(&cmd, "/DBLAKE3_NO_SSE2", "/DBLAKE3_NO_SSE41",
                 "/DBLAKE3_NO_AVX2", "/DBLAKE3_NO_AVX512");
  nob_cmd_append(&cmd, "/Isrc");
  nob_cmd_append(&cmd, nob_temp_sprintf("/Fe:build\\%s.exe", output_name));
  nob_cmd_append(&cmd, nob_temp_sprintf("/Fo:build\\"));
#else
  // GCC/Clang
  nob_cmd_append(&cmd, "clang");
  nob_cmd_append(&cmd, "-Wall", "-Wextra", "-ggdb");
  nob_cmd_append(&cmd, "-DBLAKE3_NO_SSE2", "-DBLAKE3_NO_SSE41",
                 "-DBLAKE3_NO_AVX2", "-DBLAKE3_NO_AVX512");
  nob_cmd_append(&cmd, "-Isrc");
  nob_cmd_append(&cmd, "-isysroot",
                 "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk");
  nob_cmd_append(&cmd, "-o", nob_temp_sprintf("build/%s", output_name));
#endif

// --- Source Files ---
#ifdef _WIN32
  nob_cmd_append(&cmd, "src/platform/win32_main.c");
#else
  nob_cmd_append(&cmd, "src/platform/posix_main.c");
#endif

  // Core
  nob_cmd_append(&cmd, "src/core/state.c");
  nob_cmd_append(&cmd, "src/core/crypto.c");

  // Crypto (vendored)
  nob_cmd_append(&cmd, "src/crypto/monocypher.c");
  nob_cmd_append(&cmd, "src/crypto/blake3.c");
  nob_cmd_append(&cmd, "src/crypto/blake3_dispatch.c");
  nob_cmd_append(&cmd, "src/crypto/blake3_portable.c");

  // --- Libraries ---
#ifdef _MSC_VER
  nob_cmd_append(&cmd, "ws2_32.lib", "advapi32.lib", "user32.lib",
                 "Mswsock.lib"); // user32 fallback if needed
#else
  nob_cmd_append(&cmd, "-lpthread");
#endif

  if (!nob_cmd_run_sync(cmd))
    return 1;

  return 0;
}