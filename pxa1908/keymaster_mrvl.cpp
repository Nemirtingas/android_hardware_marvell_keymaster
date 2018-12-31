/*
 * Copyright (C) 2016 The CyanogenMod Project
 *               2017 The LineageOS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <hardware/hardware.h>
#include <hardware/keymaster0.h>

#include <tee_client.h>

#include "keymaster_mrvl.h"

// For debugging
//#define LOG_NDEBUG 0

#define LOG_TAG "MRVLKeymaster"
#define UNUSED(x) (void)(x)

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <cutils/log.h>
#include <stdlib.h>
#include <string.h>

TEEC_UUID teec_uuid;
char byte_1D05[16];

struct struc_v9
{
    size_t len;
    uint8_t buff[2056];
};

void free_buff(uint8_t **buffer)
{
    if( *buffer )
    {
        delete *buffer;
        *buffer = NULL;
    }
}

enum KEYMASTER_COMMANDS
{
    KEYMASTER_GENERATE_KEYPAIR = 0x00000001,
    KEYMASTER_IMPORT_KEYPAIR   = 0x00000002,
    KEYMASTER_GET_KEYPAIR      = 0x00000003,
    KEYMASTER_DELETE_KEYPAIR   = 0x00000004,
    KEYMASTER_DELETE_ALL       = 0x00000005,
    KEYMASTER_SIGN_RSA         = 0x00000006,
    KEYMASTER_VERIFY_RSA       = 0x00000007,
};

int sub_1044( uint8_t *key_blob, size_t key_blob_length, int *a3, size_t *a4, void *buffer )
{
    uint8_t *pblob;
    uint32_t cksum;

    if( key_blob == NULL || key_blob_length <= 32 || a3 == NULL || a4 == NULL || buffer == NULL )
        return -1;

    if( memcmp(key_blob, "MARV", 4) )
        return -1;

    pblob = key_blob + 4;
    cksum = 0;
    do
    {
        cksum = *pblob++ | (cksum << 8);
    }
    while( pblob != (key_blob+8) );
    if( cksum != 1 )
        return -1;

    if( memcmp(pblob, byte_1D05, 16) )
        return -1;

    cksum = 0;
    pblob = key_blob + 24;
    do
    {
        cksum = *pblob++ | (cksum << 8);
    }
    while( pblob != (key_blob + 28) );

    *a3 = cksum;
    cksum = 0;
    do
    {
        cksum = *pblob++ | (cksum << 8);
    }
    while( pblob != (key_blob + 32) );

    *a4 = cksum;
    memcpy(buffer, pblob, cksum);

    return 0;
}

int sub_142C( char *inBuffer, int a2, uint8_t **outBuffer, size_t *size )
{
    uint8_t *buffer;
    uint8_t *tmp8;
    uint32_t *tmp32, *tmp232;
    int res = 0;

    if( inBuffer == NULL || outBuffer == NULL || size == 0 )
        return -1;

    *size = 96;
    buffer = new uint8_t[96];

    if( buffer )
    {
        //*(int32_t*)buffer = 0x5652414D;
        buffer[0] = 'M';
        buffer[1] = 'A';
        buffer[2] = 'R';
        buffer[3] = 'v';
        buffer[4] = 0;
        buffer[5] = 0;
        buffer[6] = 0;
        buffer[7] = 1;
        tmp32 = (uint32_t*)&buffer[8];
        tmp232 = (uint32_t*)byte_1D05;
        for( int i = 0; i < 4; ++i )
        {
            *tmp32++ = *tmp232++;
        }
        for( int i = 0; i < 4; ++i )
        {
            buffer[24+i] = a2 >> (0xF8 * i + 0x18);
        }
        buffer[28] = 0;
        buffer[29] = 0;
        buffer[30] = 0;
        buffer[31] = 64;
        tmp32 = (uint32_t*)&buffer[32];
        tmp232 = (uint32_t*)inBuffer;
        for( int i = 0; i < 16; ++i )
        {
            *tmp32++ = *tmp232++;
        }
        *outBuffer = buffer;
    }
    else
        res = -1;

    free_buff(&buffer);
    return res;
}

static int teec_delete_all()
{
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;

    res = TEEC_InitializeContext(0, &context);
    if( res == TEEC_SUCCESS )
    {
        res = TEEC_OpenSession(&context, &session, &teec_uuid, TEEC_LOGIN_USER, NULL, NULL, NULL);
        if ( res == TEEC_SUCCESS )
        {
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
                                                    TEEC_NONE,
                                                    TEEC_NONE,
                                                    TEEC_NONE);
            res = TEEC_InvokeCommand(&session, KEYMASTER_DELETE_ALL, &operation, NULL);
            TEEC_CloseSession(&session);
        }
        TEEC_FinalizeContext(&context);
    }
    return res;
}

static int teec_delete_keypair(void *buffer, size_t size)
{
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_SharedMemory sharedMem;
    TEEC_Operation operation;

    res = TEEC_InitializeContext(NULL, &context);
    if( res == TEEC_SUCCESS )
    {
        res = TEEC_OpenSession(&context, &session, &teec_uuid, TEEC_LOGIN_USER, NULL, NULL, NULL);
        if( res == TEEC_SUCCESS )
        {
            sharedMem.buffer = buffer;
            sharedMem.flags = TEEC_VALUE_INPUT;
            sharedMem.size = size;
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                                    TEEC_NONE,
                                                    TEEC_NONE,
                                                    TEEC_NONE);
            res = TEEC_RegisterSharedMemory(&context, &sharedMem);
            if( res == TEEC_SUCCESS )
            {
                operation.params[0].memref.parent = &sharedMem;
                operation.params[0].memref.size = size;
                operation.params[0].memref.offset = 0;

                res = TEEC_InvokeCommand(&session, KEYMASTER_DELETE_KEYPAIR, &operation, NULL);
                TEEC_ReleaseSharedMemory(&sharedMem);
            }
            TEEC_CloseSession(&session);
        }
        TEEC_FinalizeContext(&context);
    }

    return res;
}

static int teec_generate_rsa_keypair(void *buffer, uint32_t modulus_size, uint64_t public_exponent)
{
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_SharedMemory sharedMem;
    TEEC_Operation operation;

    res = TEEC_InitializeContext(0, &context);
    if ( res == TEEC_SUCCESS )
    {
        res = TEEC_OpenSession(&context, &session, &teec_uuid, TEEC_LOGIN_USER, 0, 0, 0);
        if ( res == TEEC_SUCCESS )
        {
            sharedMem.flags = TEEC_MEM_OUTPUT;
            sharedMem.buffer = buffer;
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                                    TEEC_VALUE_INPUT,
                                                    TEEC_MEMREF_PARTIAL_OUTPUT,
                                                    TEEC_NONE);
            sharedMem.size = 64;
            res = TEEC_RegisterSharedMemory(&context, &sharedMem);
            if ( res == TEEC_SUCCESS )
            {
                operation.params[0].value.a = 1;
                operation.params[0].value.b = modulus_size;

                operation.params[1].value.a = public_exponent;
                operation.params[1].value.b = 0;

                operation.params[2].memref.parent = &sharedMem;
                operation.params[2].memref.size = 64;
                operation.params[2].memref.offset = 0;
                res = TEEC_InvokeCommand(&session, KEYMASTER_GENERATE_KEYPAIR, &operation, 0);
                if ( res == TEEC_SUCCESS )
                {
                    res = TEEC_ERROR_GENERIC;
                    if ( buffer )
                        res = 0;
                }
                TEEC_ReleaseSharedMemory(&sharedMem);
            }
            TEEC_CloseSession(&session);
        }
        TEEC_FinalizeContext(&context);
    }
    return res;
}

static void* teec_get_keypair_blob(void *buffer, size_t buffer_size, size_t *key_size)
{
    void* res = NULL;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_SharedMemory inMem;
    TEEC_SharedMemory outMem;
    TEEC_Operation operation;

    if ( buffer == NULL )
        return NULL;

    if ( TEEC_InitializeContext(0, &context) )
        return NULL;

    if ( TEEC_OpenSession(&context, &session, &teec_uuid, TEEC_LOGIN_USER, 0, 0, 0) == TEEC_SUCCESS )
    {
        inMem.buffer = buffer;
        inMem.flags = TEEC_MEM_INPUT;
        inMem.size = buffer_size;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
                                                TEEC_MEMREF_PARTIAL_OUTPUT,
                                                TEEC_NONE,
                                                TEEC_NONE);
        if ( TEEC_RegisterSharedMemory(&context, &inMem) == TEEC_SUCCESS )
        {
            outMem.size = 2056;
            outMem.flags = TEEC_MEM_OUTPUT;
            if( TEEC_AllocateSharedMemory(&context, &outMem) == TEEC_SUCCESS )
            {
                operation.params[0].memref.parent = &inMem;
                operation.params[0].memref.size = buffer_size;
                operation.params[0].memref.offset = 0;

                operation.params[1].memref.parent = &outMem;
                operation.params[1].memref.size = 2056;
                operation.params[1].memref.offset = 0;

                if ( TEEC_InvokeCommand(&session, KEYMASTER_GET_KEYPAIR, &operation, 0) == TEEC_SUCCESS )
                {
                    *key_size = operation.params[1].memref.size;
                    res = malloc(*key_size);
                    if ( res )
                        memcpy(res, outMem.buffer, *key_size);
                }
                TEEC_ReleaseSharedMemory(&outMem);
            }
            TEEC_ReleaseSharedMemory(&inMem);
        }
        TEEC_CloseSession(&session);
    }
    TEEC_FinalizeContext(&context);

    return res;
}

static int teec_import_rsa_keypair(void *outBuffer, void *inBuffer, size_t size)
{
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_SharedMemory inoutMem;
    TEEC_SharedMemory outMem;
    TEEC_Operation operation;

    if ( !outBuffer || !inBuffer )
        return TEEC_ERROR_GENERIC;
    res = TEEC_InitializeContext(0, &context);
    if ( res == TEEC_SUCCESS )
    {
        res = TEEC_OpenSession(&context, &session, &teec_uuid, TEEC_LOGIN_USER, NULL, NULL, NULL);
        if ( res == TEEC_SUCCESS )
        {
            inoutMem.buffer = inBuffer;
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                                    TEEC_MEMREF_WHOLE,
                                                    TEEC_MEMREF_PARTIAL_OUTPUT,
                                                    TEEC_NONE);
            inoutMem.flags = TEEC_MEM_OUTPUT|TEEC_MEM_INPUT;
            inoutMem.size = 3 * size + 12;
            res = TEEC_RegisterSharedMemory(&context, &inoutMem);
            if ( res == TEEC_SUCCESS )
            {
                outMem.buffer = outBuffer;
                outMem.size = 64;
                outMem.flags = TEEC_MEM_OUTPUT;
                res = TEEC_RegisterSharedMemory(&context, &outMem);
                if ( res == TEEC_SUCCESS )
                {
                    operation.params[0].value.a = 1;
                    operation.params[0].tmpref.size = size;

                    operation.params[1].memref.parent = &inoutMem;
                    operation.params[1].memref.size = 3 * size + 12;
                    operation.params[1].memref.offset = 0;

                    operation.params[2].memref.parent = &outMem;
                    operation.params[2].memref.size = 64;
                    operation.params[2].memref.offset = 0;

                    res = TEEC_InvokeCommand(&session, KEYMASTER_IMPORT_KEYPAIR, &operation, 0);
                    TEEC_ReleaseSharedMemory(&outMem);
                }
                TEEC_ReleaseSharedMemory(&inoutMem);
            }
            TEEC_CloseSession(&session);
        }
        TEEC_FinalizeContext(&context);
    }
    return res;
}

static int teec_sign_rsa(void* inBuffer, int inSize, const void *buffer, void* outBuffer, size_t outSize)
{
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_SharedMemory inMem1;
    TEEC_SharedMemory inMem2;
    TEEC_SharedMemory outMem;
    TEEC_Operation operation;

    if ( !inBuffer || !buffer || !outBuffer )
        return TEEC_ERROR_GENERIC;
    res = TEEC_InitializeContext(0, &context);
    if ( res == TEEC_SUCCESS )
    {
        res = TEEC_OpenSession(&context, &session, &teec_uuid, TEEC_LOGIN_USER, 0, 0, 0);
        if ( res == TEEC_SUCCESS )
        {
            inMem1.buffer = (void *)inBuffer;
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                                    TEEC_MEMREF_PARTIAL_INPUT,
                                                    TEEC_MEMREF_PARTIAL_INPUT,
                                                    TEEC_MEMREF_PARTIAL_OUTPUT);
            inMem1.size = inSize;
            inMem1.flags = TEEC_MEM_INPUT;
            res = TEEC_RegisterSharedMemory(&context, &inMem1);
            if ( res == TEEC_SUCCESS )
            {
                inMem2.size = outSize;
                inMem2.flags = TEEC_MEM_INPUT;
                res = TEEC_AllocateSharedMemory(&context, &inMem2);
                if ( res == TEEC_SUCCESS )
                {
                    memcpy(inMem2.buffer, buffer, outSize);
                    outMem.size = outSize;
                    outMem.buffer = (void *)outBuffer;
                    outMem.flags = TEEC_MEM_INPUT;
                    res = TEEC_RegisterSharedMemory(&context, &outMem);
                    if ( res == TEEC_SUCCESS )
                    {
                        operation.params[0].value.a = 1;
                        operation.params[0].value.b = outSize;

                        operation.params[1].memref.parent = &inMem1;
                        operation.params[1].memref.size = inSize;
                        operation.params[1].memref.offset = 0;

                        operation.params[2].memref.parent = &inMem2;
                        operation.params[2].memref.size = outSize;
                        operation.params[2].memref.offset = 0;

                        operation.params[3].memref.parent = &outMem;
                        operation.params[3].memref.size = outSize;
                        operation.params[3].memref.offset = 0;

                        res = TEEC_InvokeCommand(&session, KEYMASTER_SIGN_RSA, &operation, 0);
                        TEEC_ReleaseSharedMemory(&outMem);
                    }
                    TEEC_ReleaseSharedMemory(&inMem2);
                }
                TEEC_ReleaseSharedMemory(&inMem1);
            }
            TEEC_CloseSession(&session);
        }
        TEEC_FinalizeContext(&context);
    }
    return res;
}

static int teec_verify_rsa(void *inBuffer, int inSize1, const void *inBuffer2, void *inBuffer3, size_t inSize3)
{
    TEEC_Result res;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_SharedMemory inMem1;
    TEEC_SharedMemory inMem2;
    TEEC_SharedMemory inMem3;
    TEEC_Operation operation;

    if ( !inBuffer || !inBuffer2 || !inBuffer3 )
        return TEEC_ERROR_GENERIC;

    res = TEEC_InitializeContext(0, &context);
    if ( res == TEEC_SUCCESS )
    {
        res = TEEC_OpenSession(&context, (TEEC_Session *)&session, &teec_uuid, TEEC_LOGIN_USER, 0, 0, 0);
        if ( res == TEEC_SUCCESS )
        {
            inMem1.buffer = inBuffer;
            operation.started = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
                                                 TEEC_MEMREF_PARTIAL_INPUT,
                                                 TEEC_MEMREF_PARTIAL_INPUT,
                                                 TEEC_MEMREF_PARTIAL_INPUT);
            inMem1.size = inSize1;
            inMem1.flags = TEEC_MEM_INPUT;
            res = TEEC_RegisterSharedMemory(&context, &inMem1);
            if ( res == TEEC_SUCCESS )
            {
                inMem2.size = inSize3;
                inMem2.flags = TEEC_MEM_INPUT;
                res = TEEC_AllocateSharedMemory(&context, &inMem2);
                if ( res == TEEC_SUCCESS )
                {
                    memcpy(inMem2.buffer, inBuffer2, inSize3);
                    inMem3.size = inSize3;
                    inMem3.flags = TEEC_MEM_INPUT;
                    res = TEEC_AllocateSharedMemory(&context, &inMem3);
                    memcpy(inMem3.buffer, inBuffer3, inSize3);
                    if ( res == TEEC_SUCCESS )
                    {
                        operation.params[0].value.a = 1;
                        operation.params[0].value.b = -1;

                        operation.params[1].memref.parent = &inMem1;
                        operation.params[1].memref.size = inSize1;
                        operation.params[1].memref.offset = 0;

                        operation.params[2].memref.parent = &inMem2;
                        operation.params[2].memref.size = inSize3;
                        operation.params[2].memref.offset = 0;

                        operation.params[3].memref.parent = &inMem3;
                        operation.params[3].memref.size = inSize3;
                        operation.params[3].memref.offset = 0;

                        res = TEEC_InvokeCommand(&session, KEYMASTER_VERIFY_RSA, &operation, 0);
                        if ( res == TEEC_SUCCESS )
                            res = operation.params[0].value.b;

                        TEEC_ReleaseSharedMemory(&inMem3);
                    }
                    TEEC_ReleaseSharedMemory(&inMem2);
                }
                TEEC_ReleaseSharedMemory(&inMem1);
            }
            TEEC_CloseSession((TEEC_Session *)&session);
        }
        TEEC_FinalizeContext(&context);
    }
    return res;
}

static int marvell_keymaster_close(hw_device_t *module)
{
    operator delete(module);
    return 0;
}

static int marvell_keymaster_delete_all(const struct keymaster0_device *device)
{
    if( teec_delete_all() )
        return -1;

    return 0;
}

static int marvell_keymaster_delete_keypair(const struct keymaster0_device* dev,
        const uint8_t* key_blob, const size_t key_blob_length)
{
  size_t size = 0;
  int v7 = 0;
  char buffer[64] = {0};

  if ( !key_blob || !key_blob_length || sub_1044((uint8_t*)key_blob, key_blob_length, &v7, &size, &buffer) )
    return -1;

  if ( teec_delete_keypair(&buffer, size) )
    return -1;

  return 0;
}

static int marvell_keymaster_generate_keypair(const struct keymaster0_device *dev,
        const keymaster_keypair_t key_type, const void *key_params,
        uint8_t **key_blob, size_t *key_blob_length)
{
  char s[64] = {0};
  keymaster_rsa_keygen_params_t* rsa_params = (keymaster_rsa_keygen_params_t*) key_params;

  if ( !rsa_params
    || !key_blob
    || !key_blob_length
    || key_type != TYPE_RSA
    || !rsa_params->public_exponent
    || teec_generate_rsa_keypair(s, rsa_params->modulus_size, rsa_params->public_exponent) )
  {
    return -1;
  }

  if ( sub_142C(s, TYPE_RSA, key_blob, key_blob_length) )
    return -1;

  return 0;
}

static int marvell_keymaster_sign_data(const struct keymaster0_device *dev,
        const void *params, const uint8_t *key_blob,
        const size_t key_blob_length, const uint8_t *data,
        const size_t data_length, uint8_t **signed_data, size_t *signed_data_length)
{
    uint8_t *buffer;
    int result;
    size_t size = 0;
    int v17 = 0;
    char s[64] = {0};

    keymaster_rsa_sign_params_t* signing_params = (keymaster_rsa_sign_params_t*) params;

    if ( !signing_params
        || !data
        || !data_length
        || !signed_data
        || !signed_data_length
        || sub_1044((uint8_t *)key_blob, key_blob_length, &v17, &size, &s)
        || v17 != 1 )
    {
        return -1;
    }

    if ( !size
        || signing_params->digest_type != DIGEST_NONE
        || signing_params->padding_type != PADDING_NONE )
        return -1;

    buffer = (uint8_t *)malloc(data_length);
    if ( !buffer || teec_sign_rsa(&s, size, data, buffer, data_length) )
    {
        result = -1;
    }
    else
    {
        *signed_data_length = data_length;
        *signed_data = buffer;
        buffer = 0;
        result = 0;
    }
    free_buff(&buffer);
    return result;
}

static int marvell_keymaster_verify_data(const struct keymaster0_device *dev,
        const void *params, const uint8_t *key_blob,
        const size_t key_blob_length, const uint8_t *signed_data,
        const size_t signed_data_length, const uint8_t *signature, const size_t signature_length)
{
    int result; // r0
    size_t size = 0;
    int v13 = 0;
    char s[64] = {0};

    keymaster_rsa_sign_params_t* signing_params = (keymaster_rsa_sign_params_t*) params;

    if ( signing_params
    && key_blob
    && key_blob_length
    && signed_data
    && signed_data_length
    && signature
    && signature_length
    && !sub_1044((uint8_t *)key_blob, key_blob_length, &v13, &size, s)
    && v13 == 1
    && size
    && signing_params->digest_type == DIGEST_NONE
    && signing_params->padding_type == PADDING_NONE
    && signature_length == signed_data_length )
    {
        return teec_verify_rsa(s, size, signature, (void*)signed_data, signature_length);
    }

    return -1;
}

static int marvell_keymaster_get_keypair_public(const struct keymaster0_device *dev,
        const uint8_t *keyBlob, const size_t keyBlobLength,
        uint8_t **x509_data, size_t *x509_data_length)
{
    int res;
    RSA *rsa;
    int32_t pubkeyLength;
    size_t length = 0;
    size_t length2 = 0;
    struc_v9 *v9;
    size_t key_size = 0;
    char buffer[64] = {0};
    BIGNUM *bnum1;
    BIGNUM *bnum2;
    uint8_t *pubkey_blob;
    EVP_PKEY *pkey;
    int v22 = 0;
    size_t bufferSize = 0;

    if ( keyBlob == NULL
      || keyBlobLength == 0
      || x509_data == NULL
      || x509_data_length == NULL
      || (res = sub_1044((uint8_t *)keyBlob, keyBlobLength, &v22, &bufferSize, &buffer)) != 0
      || (v9 = (struc_v9*)teec_get_keypair_blob(&buffer, bufferSize, &key_size)) == 0
      || (pkey = EVP_PKEY_new()) == 0 )
    {
        return -1;
    }
    rsa = RSA_new();
    bnum1 = BN_new();
    bnum2 = BN_new();
    length = v9->len;
    BN_bin2bn(v9->buff, length, bnum1);

    length2 = *(size_t*)&v9->buff[length];
    BN_bin2bn(&v9->buff[length+4], length2, bnum2);
    rsa->d = bnum1;
    rsa->p = bnum2;
    if ( !EVP_PKEY_set1_RSA(pkey, rsa) )
    {
        EVP_PKEY_free(pkey);
        return -1;
    }

    pubkeyLength = i2d_PUBKEY(pkey, NULL);
    if ( pubkeyLength <= 0 )
    {
        EVP_PKEY_free(pkey);
        return -1;
    }

    pubkey_blob = (uint8_t *)malloc(pubkeyLength);
    if ( pubkey_blob && i2d_PUBKEY(pkey, &pubkey_blob) == pubkeyLength )
    {
        *x509_data = pubkey_blob;
        *x509_data_length = pubkeyLength;
        // Set in to null so we don't free it.
        pubkey_blob = NULL;
        free(v9);
        RSA_free(rsa);
    }
    else
    {
        res = -1;
    }
    free_buff(&pubkey_blob);
    EVP_PKEY_free(pkey);
    return res;
}

static int marvell_keymaster_import_keypair(const keymaster0_device_t* dev,
        const uint8_t* key, const size_t key_length,
        uint8_t** keyBlob, size_t* keyBlobLength)
{
    int res;
    uint8_t buffer[64] = {0};
    uint8_t *rsa_key;
    size_t rsa_key_length;
    EVP_PKEY *evp_key;
    RSA *rsa;
    PKCS8_PRIV_KEY_INFO *pkey;
    int32_t numBits;
    int32_t numBytesP, numBytesQ, numBytesD;

    if( key == NULL
     || key_length == 0
     || keyBlob == NULL
     || keyBlobLength == NULL
     || (pkey = d2i_PKCS8_PRIV_KEY_INFO(0, &key, key_length)) == NULL )
    {
        return -1;
    }

    evp_key = EVP_PKCS82PKEY(pkey);
    if( evp_key == NULL )
    {
        PKCS8_PRIV_KEY_INFO_free(pkey);
        return -1;
    }

    if( EVP_PKEY_type(evp_key->references) == EVP_PKEY_RSA )
    {
        rsa = evp_key->pkey.rsa;
        numBits = BN_num_bits(rsa->d);
        numBits += 7;
        if( numBits < 0 )
            numBits += 7;

        numBytesD = numBits/8;

        numBits = BN_num_bits(rsa->p);
        numBits += 7;
        if( numBits < 0 )
            numBits += 7;

        numBytesP = numBits/8;

        numBits = BN_num_bits(rsa->q);
        numBits += 7;
        if( numBits < 0 )
            numBits += 7;

        numBytesQ = numBits/8;

        rsa_key_length = 3 * (numBytesD+4);
        rsa_key = (uint8_t*)malloc(rsa_key_length);
        if( rsa_key == NULL )
        {
            EVP_PKEY_free(evp_key);
            PKCS8_PRIV_KEY_INFO_free(pkey);
            return -1;
        }

        memset(rsa_key, 0, rsa_key_length);
        *(int32_t*)&rsa_key[0] = numBytesD;
        BN_bn2bin(rsa->d, &rsa_key[4]);

        *(int32_t*)&rsa_key[numBytesD+4] = numBytesP;
        BN_bn2bin(rsa->p, &rsa_key[numBytesD+4 + 4]);

        *(int32_t*)&rsa_key[numBytesD+4 + numBytesP+4] = numBytesQ;
        BN_bn2bin(rsa->q, &rsa_key[numBytesD+4 + numBytesP+4 + 4]);

        if( teec_import_rsa_keypair(buffer, rsa_key, numBytesD) )
        {
            EVP_PKEY_free(evp_key);
            PKCS8_PRIV_KEY_INFO_free(pkey);
            return -1;
        }

        free(rsa_key);
        res = sub_142C((char*)buffer, TYPE_RSA, keyBlob, keyBlobLength);
        if( res )
            res = -1;
    }

    return res;
}

/*
 * Generic device handling
 */
static int marvell_keymaster_open(const hw_module_t* module, const char* name,
        hw_device_t** device)
{
    keymaster0_device * dev;

    if (strcmp(name, KEYSTORE_KEYMASTER) != 0)
        return -EINVAL;

    dev = new keymaster0_device;
    if( dev == NULL )
        return -ENOMEM;

    dev->common.tag = HARDWARE_DEVICE_TAG;
    dev->common.version = 1;
    dev->common.module = (struct hw_module_t*) module;
    dev->common.close = marvell_keymaster_close;
    dev->flags = 0;

    dev->common.close       = marvell_keymaster_close;
    dev->generate_keypair   = marvell_keymaster_generate_keypair;
    dev->import_keypair     = marvell_keymaster_import_keypair;
    dev->get_keypair_public = marvell_keymaster_get_keypair_public;
    dev->delete_keypair     = marvell_keymaster_delete_keypair;
    dev->delete_all         = marvell_keymaster_delete_all;
    dev->sign_data          = marvell_keymaster_sign_data;
    dev->verify_data        = marvell_keymaster_verify_data;

    *device = (hw_device_t*)dev;

    return 0;
}

static struct hw_module_methods_t keystore_module_methods = {
    .open = marvell_keymaster_open,
};

struct keystore_module HAL_MODULE_INFO_SYM
__attribute__ ((visibility ("default"))) = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .module_api_version = KEYMASTER_MODULE_API_VERSION_0_2,
        .hal_api_version = HARDWARE_HAL_API_VERSION,
        .id = KEYSTORE_HARDWARE_MODULE_ID,
        .name = "Marvell Keymaster HAL",
        .author = "Nemirtingas (Maxime P)",
        .methods = &keystore_module_methods,
        .dso = 0,
        .reserved = {},
    },
};
