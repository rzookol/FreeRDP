# libNLA prototype

This directory hosts a minimal, dependency-light scaffold for experimenting
with NLA/CredSSP support that could be shared between FreeRDP and rdesktop
without dragging in the full FreeRDP dependency graph. The current
implementation exposes a small C API in `include/libnla/nla.h` and builds a
static library (`libnla`) via the accompanying `CMakeLists.txt`.

## Current implementation

* Uses the WinPR SSPI stack (NTLM/Kerberos via the Negotiate package) to create
  a client-side security context and drive token exchanges without depending on
  Windows SSPI or Samba.
* Provides helpers to set ANSI identities, initialize the client context for a
  target SPN and process incoming tokens while emitting the next token to send.
* Releases all SSPI handles and identity material during `libnla_reset`/`libnla_free`
  so callers can re-use a single context across attempts.

## Integration sketch

1. Enable the library by adding `add_subdirectory(libNLA)` to your top-level
   CMake configuration (FreeRDP now enables `BUILD_LIBNLA` by default and uses
   it to source the SSPI table for CredSSP/NLA).
2. Link against the `libnla` target and drive the state machine by feeding
   server tokens into `libnla_process`, sending the returned tokens back to the
   peer until `LIBNLA_SUCCESS` is returned.
3. Because the code reuses the WinPR SSPI facilities directly, it remains
   portable across the same platforms WinPR supports (including Linux) without
   additional third-party authentication stacks.

