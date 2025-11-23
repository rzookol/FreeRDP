#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include <winpr/sspi.h>

#include "libnla/nla.h"

struct libnla_context
{
    SecurityFunctionTable* table;
    CredHandle credentials;
    CtxtHandle context;
    SecPkgInfoA* packageInfo;
    SEC_WINNT_AUTH_IDENTITY identity;
    char* targetSpn;
    char* packageName;
    BOOL haveCredentials;
    BOOL haveContext;
};

static void libnla_free_identity(libnla_context* ctx)
{
    if (!ctx)
        return;

    free(ctx->identity.Domain);
    free(ctx->identity.User);
    free(ctx->identity.Password);
    ZeroMemory(&ctx->identity, sizeof(ctx->identity));
}

static libnla_status libnla_dup_string(const char* src, unsigned char** dst, unsigned long* len)
{
    free(*dst);
    *dst = NULL;
    *len = 0;

    if (!src)
        return LIBNLA_SUCCESS;

    const size_t slen = strlen(src);
    unsigned char* copy = calloc(slen + 1, sizeof(unsigned char));
    if (!copy)
        return LIBNLA_ERROR_INTERNAL;

    memcpy(copy, src, slen);
    *dst = copy;
    if (slen > ULONG_MAX)
        return LIBNLA_ERROR_INTERNAL;
    *len = (unsigned long)slen;
    return LIBNLA_SUCCESS;
}

libnla_context* libnla_new(void)
{
    libnla_context* ctx = (libnla_context*)calloc(1, sizeof(libnla_context));
    return ctx;
}

libnla_status libnla_set_identity(libnla_context* ctx, const char* domain, const char* user,
                                 const char* password)
{
    if (!ctx)
        return LIBNLA_ERROR_INVALID_STATE;

    libnla_free_identity(ctx);

    libnla_status status = libnla_dup_string(domain, &ctx->identity.Domain, &ctx->identity.DomainLength);
    if (status != LIBNLA_SUCCESS)
        return status;

    status = libnla_dup_string(user, &ctx->identity.User, &ctx->identity.UserLength);
    if (status != LIBNLA_SUCCESS)
        return status;

    status = libnla_dup_string(password, &ctx->identity.Password, &ctx->identity.PasswordLength);
    if (status != LIBNLA_SUCCESS)
        return status;

    ctx->identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    return LIBNLA_SUCCESS;
}

libnla_status libnla_client_init(libnla_context* ctx, const char* target_spn, const char* package_name)
{
    if (!ctx)
        return LIBNLA_ERROR_INVALID_STATE;

    const char* pkg = package_name ? package_name : "Negotiate";

    free(ctx->targetSpn);
    ctx->targetSpn = target_spn ? strdup(target_spn) : NULL;

    free(ctx->packageName);
    ctx->packageName = strdup(pkg);

    if (!ctx->packageName)
        return LIBNLA_ERROR_INTERNAL;

    if (!ctx->table)
        ctx->table = InitSecurityInterfaceExA(0);

    if (!ctx->table)
        return LIBNLA_ERROR_NOT_INITIALIZED;

    if (ctx->haveContext)
    {
        ctx->table->DeleteSecurityContext(&ctx->context);
        ctx->haveContext = FALSE;
    }

    if (ctx->haveCredentials)
    {
        ctx->table->FreeCredentialsHandle(&ctx->credentials);
        ctx->haveCredentials = FALSE;
    }

    if (ctx->packageInfo)
    {
        ctx->table->FreeContextBuffer(ctx->packageInfo);
        ctx->packageInfo = NULL;
    }

    const SECURITY_STATUS pkgStatus = ctx->table->QuerySecurityPackageInfoA((SEC_CHAR*)pkg, &ctx->packageInfo);
    if (pkgStatus != SEC_E_OK)
        return LIBNLA_ERROR_SSPI;

    TimeStamp expiry = { 0 };
    const SECURITY_STATUS credStatus = ctx->table->AcquireCredentialsHandleA(
        NULL, (SEC_CHAR*)pkg, SECPKG_CRED_OUTBOUND, NULL, &ctx->identity, NULL, NULL, &ctx->credentials,
        &expiry);

    if (credStatus != SEC_E_OK)
        return LIBNLA_ERROR_SSPI;

    ctx->haveCredentials = TRUE;
    ctx->haveContext = FALSE;
    return LIBNLA_SUCCESS;
}

libnla_status libnla_process(libnla_context* ctx, const unsigned char* token, unsigned int length,
                             unsigned char* out_token, unsigned int* out_length)
{
    if (!ctx || !out_token || !out_length)
        return LIBNLA_ERROR_INVALID_STATE;
    if (!ctx->haveCredentials)
        return LIBNLA_ERROR_NOT_INITIALIZED;

    SecBuffer outBuffer = { 0 };
    outBuffer.BufferType = SECBUFFER_TOKEN;
    outBuffer.cbBuffer = 0;
    outBuffer.pvBuffer = NULL;

    SecBuffer inBuffers[2];
    ZeroMemory(inBuffers, sizeof(inBuffers));

    SecBufferDesc outBufferDesc = { 0 };
    outBufferDesc.ulVersion = SECBUFFER_VERSION;
    outBufferDesc.cBuffers = 1;
    outBufferDesc.pBuffers = &outBuffer;

    SecBufferDesc inBufferDesc = { 0 };
    inBufferDesc.ulVersion = SECBUFFER_VERSION;
    inBufferDesc.cBuffers = 0;
    inBufferDesc.pBuffers = inBuffers;

    if (token && length > 0)
    {
        inBuffers[0].BufferType = SECBUFFER_TOKEN;
        inBuffers[0].pvBuffer = (void*)token;
        inBuffers[0].cbBuffer = length;

        inBufferDesc.cBuffers = 1;
    }

    ULONG contextAttributes = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY |
                               ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_MUTUAL_AUTH |
                               ISC_REQ_MANUAL_CRED_VALIDATION;

    const SECURITY_STATUS status = ctx->table->InitializeSecurityContextA(
        &ctx->credentials, ctx->haveContext ? &ctx->context : NULL, (SEC_CHAR*)ctx->targetSpn, contextAttributes,
        0, SECURITY_NATIVE_DREP, inBufferDesc.cBuffers ? &inBufferDesc : NULL, 0, &ctx->context, &outBufferDesc,
        &contextAttributes, NULL);

    if (status == SEC_E_OK)
        ctx->haveContext = TRUE;
    else if (status == SEC_I_CONTINUE_NEEDED)
        ctx->haveContext = TRUE;
    else
    {
        if (outBuffer.pvBuffer)
            ctx->table->FreeContextBuffer(outBuffer.pvBuffer);
        return LIBNLA_ERROR_SSPI;
    }

    libnla_status result = LIBNLA_SUCCESS;

    if (outBuffer.cbBuffer > 0 && outBuffer.pvBuffer)
    {
        const unsigned int capacity = *out_length;
        if (outBuffer.cbBuffer > capacity)
        {
            ctx->table->FreeContextBuffer(outBuffer.pvBuffer);
            return LIBNLA_ERROR_INSUFFICIENT_BUFFER;
        }

        memcpy(out_token, outBuffer.pvBuffer, outBuffer.cbBuffer);
        *out_length = outBuffer.cbBuffer;
    }
    else
        *out_length = 0;

    if (outBuffer.pvBuffer)
        ctx->table->FreeContextBuffer(outBuffer.pvBuffer);

    if (status == SEC_I_CONTINUE_NEEDED)
        result = LIBNLA_CONTINUE;

    return result;
}

libnla_status libnla_reset(libnla_context* ctx)
{
    if (!ctx)
        return LIBNLA_ERROR_INVALID_STATE;

    if (ctx->table)
    {
        if (ctx->haveContext)
            ctx->table->DeleteSecurityContext(&ctx->context);
        if (ctx->haveCredentials)
            ctx->table->FreeCredentialsHandle(&ctx->credentials);
        if (ctx->packageInfo)
            ctx->table->FreeContextBuffer(ctx->packageInfo);
    }

    ctx->haveContext = FALSE;
    ctx->haveCredentials = FALSE;
    ctx->packageInfo = NULL;

    free(ctx->targetSpn);
    ctx->targetSpn = NULL;

    free(ctx->packageName);
    ctx->packageName = NULL;

    libnla_free_identity(ctx);

    return LIBNLA_SUCCESS;
}

void libnla_free(libnla_context* ctx)
{
    if (!ctx)
        return;

    libnla_reset(ctx);
    free(ctx);
}

