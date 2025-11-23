#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Lightweight NLA/CredSSP helper API intended to encapsulate the authentication
 * state machine without requiring the full FreeRDP dependency graph.
 */

typedef struct libnla_context libnla_context;

typedef enum
{
    LIBNLA_SUCCESS = 0,
    LIBNLA_CONTINUE = 1,
    LIBNLA_ERROR_INVALID_STATE = -1,
    LIBNLA_ERROR_NOT_INITIALIZED = -2,
    LIBNLA_ERROR_SSPI = -3,
    LIBNLA_ERROR_INSUFFICIENT_BUFFER = -4,
    LIBNLA_ERROR_INTERNAL = -5
} libnla_status;

/**
 * Create a new NLA context. The caller owns the returned pointer and must call
 * libnla_free when finished.
 */
libnla_context* libnla_new(void);

/**
 * Configure the identity used for outbound authentication. All parameters may
 * be NULL for anonymous authentication, but typical usage supplies UTF-8
 * encoded domain, username and password strings. The strings are copied into
 * the context and can be freed by the caller after this call returns.
 */
libnla_status libnla_set_identity(libnla_context* ctx, const char* domain, const char* user,
                                 const char* password);

/**
 * Prepare the client-side security context. The target SPN must be provided
 * for mutual authentication. If package_name is NULL, the default "Negotiate"
 * SSP will be used.
 */
libnla_status libnla_client_init(libnla_context* ctx, const char* target_spn, const char* package_name);

/**
 * Process an incoming authentication token and emit the next token to send to
 * the peer. The caller provides input via `token`/`length` and supplies the
 * capacity of `out_token` through `*out_length` on entry; the function writes
 * the produced token size back to `*out_length` on success.
 */
libnla_status libnla_process(libnla_context* ctx, const unsigned char* token, unsigned int length,
                             unsigned char* out_token, unsigned int* out_length);

/**
 * Reset the context to its initial state, releasing any allocated security
 * handles and identity information.
 */
libnla_status libnla_reset(libnla_context* ctx);

/**
 * Free a context allocated by libnla_new.
 */
void libnla_free(libnla_context* ctx);

#ifdef __cplusplus
}
#endif
