/*
 * Encryption Functions Module
 *
 * This module provides commands that can be used to encrypt or decrypt data.
 *
 * Copyright (C) 2023 Brian O'Hagan
 *
 */

#include "tlsInt.h"
#include "tclOpts.h"
#include <tcl.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#endif

/* Encryption functions */
#define TYPE_MD		0x010
#define TYPE_HMAC	0x020
#define TYPE_CMAC	0x040
#define TYPE_MAC	0x080
#define TYPE_ENCRYPT	0x100
#define TYPE_DECRYPT	0x200
#define TYPE_SIGN	0x400
#define TYPE_VERIFY	0x800


/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * CryptoDataHandler --
 *
 *	Perform encryption function on a block of data and return result.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result or error message
 *
 *-------------------------------------------------------------------
 */
int
Encrypt_DataHandler(Tcl_Interp *interp, int type, Tcl_Obj *dataObj, Tcl_Obj *cipherObj,
	Tcl_Obj *digestObj, Tcl_Obj *keyObj, Tcl_Obj *ivObj) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    char *cipherName =  NULL, *data = NULL, *key = NULL, *iv = NULL;
    int cipher_len = 0, data_len = 0, key_len = 0, iv_len = 0, out_len = 0, tmplen, res;
    unsigned char *outbuf;
    Tcl_Obj *resultObj;

    dprintf("Called");

    if (cipherObj != NULL) {
	cipherName = Tcl_GetStringFromObj(cipherObj, &cipher_len);
    }
    if (keyObj != NULL) {
	key = Tcl_GetStringFromObj(keyObj, &key_len);
    }
    if (ivObj != NULL) {
	iv = Tcl_GetStringFromObj(ivObj, &iv_len);
    }
    if (dataObj != NULL) {
	data = Tcl_GetByteArrayFromObj(dataObj, &data_len);
    } else {
	Tcl_AppendResult(interp, "No data", NULL);
    }

    /* Get cipher name */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    cipher = EVP_get_cipherbyname(cipherName);
#else
    cipher = EVP_CIPHER_fetch(NULL, cipherName, NULL);
#endif
    if (cipher == NULL) {
	Tcl_AppendResult(interp, "Invalid cipher: ", cipherName, NULL);
	return TCL_ERROR;
    }

    /* Allocate storage for encrypted data. Size should be data size + block size. */
    resultObj = Tcl_NewObj();
    outbuf = Tcl_SetByteArrayLength(resultObj, data_len+1024);
    if (resultObj == NULL || outbuf == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Create and initialize the context */
    if((ctx = EVP_CIPHER_CTX_new()) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	Tcl_DecrRefCount(resultObj);
	return TCL_ERROR;
    }

    /* Initialize the operation. Need appropriate key and iv size. */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    } else {
	res = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    }
#else
	OSSL_PARAM params[2];
	int index = 0;

	if (iv != NULL) {
	    params[index++] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_IV, (void *) iv, (size_t) iv_len);
	}
	params[index] = OSSL_PARAM_construct_end();

    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptInit_ex2(ctx, cipher, key, iv, params);
    } else {
	res = EVP_DecryptInit_ex2(ctx, cipher, key, iv, params);
    }
#endif

    if(!res) {
	Tcl_AppendResult(interp, "Initialize failed: ", REASON(), NULL);
	Tcl_DecrRefCount(resultObj);
	EVP_CIPHER_CTX_free(ctx);
	return TCL_ERROR;
    }

    /* Encrypt/decrypt data */
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptUpdate(ctx, outbuf, &out_len, data, data_len);
    } else {
	res = EVP_DecryptUpdate(ctx, outbuf, &out_len, data, data_len);
    }

    if (!res) {
	Tcl_AppendResult(interp, "Update failed: ", REASON(), NULL);
	Tcl_DecrRefCount(resultObj);
	EVP_CIPHER_CTX_free(ctx);
	return TCL_ERROR;
    }

    /* Finalize data */
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptFinal_ex(ctx, outbuf+out_len, &tmplen);
    } else {
	res = EVP_DecryptFinal_ex(ctx, outbuf+out_len, &tmplen);
    }

    if (!res) {
	Tcl_AppendResult(interp, "Finalize failed: ", REASON(), NULL);
	Tcl_DecrRefCount(resultObj);
	EVP_CIPHER_CTX_free(ctx);
	return TCL_ERROR;
    }

    out_len += tmplen;
    outbuf = Tcl_SetByteArrayLength(resultObj, out_len);

    /* Set return result */
    Tcl_SetObjResult(interp, resultObj);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * EncryptionMain --
 *
 *	Perform encryption function and return result.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result or error message
 *
 *-------------------------------------------------------------------
 */
static int EncryptionMain(int type, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int res = TCL_OK;
    Tcl_Obj *cipherObj = NULL, *cmdObj = NULL, *dataObj = NULL, *digestObj = NULL;
    Tcl_Obj *inFileObj = NULL, *outFileObj = NULL, *keyObj = NULL, *ivObj = NULL;
    const char *channel = NULL, *opt;
    const EVP_MD *md = NULL;
    const EVP_CIPHER *cipher = NULL;

    dprintf("Called");

    /* Clear interp result */
    Tcl_ResetResult(interp);

    /* Validate arg count */
    if (objc < 3 || objc > 12) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-cipher name? ?-digest name? ?-key key? ?-iv string? [-data data]");
	return TCL_ERROR;
    }

    /* Get options */
    for (int idx = 1; idx < objc; idx++) {
	opt = Tcl_GetStringFromObj(objv[idx], NULL);

	if (opt[0] != '-') {
	    break;
	}

	OPTOBJ("-cipher", cipherObj);
	OPTOBJ("-data", dataObj);
	OPTOBJ("-digest", digestObj);
	OPTOBJ("-key", keyObj);
	OPTOBJ("-iv", ivObj);

	OPTBAD("option", "-cipher, -data, -digest, -key, or -iv");
	return TCL_ERROR;
    }

    /* Check for required options */
    if (cipherObj == NULL) {
	Tcl_AppendResult(interp, "No cipher", NULL);
    } else if (keyObj == NULL) {
	Tcl_AppendResult(interp, "No key", NULL);
	return TCL_ERROR;
    }

    /* Perform encryption function on file, stacked channel, using instance command, or data blob */
    if (dataObj != NULL) {
	res = Encrypt_DataHandler(interp, type, dataObj, cipherObj, digestObj, keyObj, ivObj);
    } else {
	Tcl_AppendResult(interp, "No operation specified: Use -data option", NULL);
	res = TCL_ERROR;
    }
    return res;
}

/*
 *-------------------------------------------------------------------
 *
 * Encryption Commands --
 *
 *	Perform encryption function and return results
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Command dependent
 *
 *-------------------------------------------------------------------
 */
static int EncryptObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return EncryptionMain(TYPE_ENCRYPT, interp, objc, objv);
}

static int DecryptObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return EncryptionMain(TYPE_DECRYPT, interp, objc, objv);
}

/*
 *-------------------------------------------------------------------
 *
 * Encrypt_Initialize --
 *
 *	Create namespace, commands, and register package version
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Creates commands
 *
 *-------------------------------------------------------------------
 */
int Tls_EncryptCommands(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tls::encrypt", EncryptObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::decrypt", DecryptObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
}

