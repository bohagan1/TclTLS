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
 * EncryptInitialize --
 *
 *	Initialize an encryption function
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR for failure with result set
 *	to error message.
 *
 * Side effects:
 *	No result or error message
 *
 *-------------------------------------------------------------------
 */
int EncryptInitialize(Tcl_Interp *interp, int type, EVP_CIPHER_CTX **ctx,
	Tcl_Obj *cipherObj, Tcl_Obj *keyObj, Tcl_Obj *ivObj) {
    const EVP_CIPHER *cipher;
    char *cipherName =  NULL, *key = NULL, *iv = NULL;
    int cipher_len = 0, data_len = 0, key_len = 0, iv_len = 0, res;

    dprintf("Called");

    /* Get encryption parameters */
    if (cipherObj != NULL) {
	cipherName = Tcl_GetStringFromObj(cipherObj, &cipher_len);
    }
    if (keyObj != NULL) {
	key = Tcl_GetStringFromObj(keyObj, &key_len);
    }
    if (ivObj != NULL) {
	iv = Tcl_GetStringFromObj(ivObj, &iv_len);
    }

    /* Get cipher name */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    cipher = EVP_get_cipherbyname(cipherName);
#else
    cipher = EVP_CIPHER_fetch(NULL, cipherName, NULL);
#endif
    if (cipher == NULL) {
	Tcl_AppendResult(interp, "Invalid cipher: \"", cipherName, "\"", NULL);
	return TCL_ERROR;
    }

    /* Create and initialize the context */
    if((*ctx = EVP_CIPHER_CTX_new()) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Initialize the operation. Need appropriate key and iv size. */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptInit_ex(*ctx, cipher, NULL, key, iv);
    } else {
	res = EVP_DecryptInit_ex(*ctx, cipher, NULL, key, iv);
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
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * EncryptUpdate --
 *
 *	Update an encryption function with data
 *
 * Returns:
 *	1 if successful or 0 for failure
 *
 * Side effects:
 *	Adds encrypted data to buffer or sets result to error message
 *
 *-------------------------------------------------------------------
 */
int EncryptUpdate(Tcl_Interp *interp, int type, EVP_CIPHER_CTX *ctx, unsigned char *outbuf,
	int *out_len, unsigned char *data, int data_len) {
    int res, len = 0;

    dprintf("Called");

    /* Encrypt/decrypt data */
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptUpdate(ctx, outbuf, out_len, data, data_len);
    } else {
	res = EVP_DecryptUpdate(ctx, outbuf, out_len, data, data_len);
    }

    if (res) {
	*out_len += len;
	return TCL_OK;
    } else {
	Tcl_AppendResult(interp, "Update failed: ", REASON(), NULL);
	return TCL_ERROR;
    }
}

/*
 *-------------------------------------------------------------------
 *
 * EncryptFinalize --
 *
 *	Finalize an encryption function
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR for failure with result set
 *	to error message.
 *
 * Side effects:
 *	Adds encrypted data to buffer or sets result to error message
 *
 *-------------------------------------------------------------------
 */
int EncryptFinalize(Tcl_Interp *interp, int type, EVP_CIPHER_CTX *ctx, unsigned char *outbuf,
	int *out_len) {
    int res, len = 0;

    dprintf("Called");

    /* Finalize data */
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptFinal_ex(ctx, outbuf, out_len);
    } else {
	res = EVP_DecryptFinal_ex(ctx, outbuf, out_len);
    }

    if (res) {
	*out_len += len;
	return TCL_OK;
    } else {
	Tcl_AppendResult(interp, "Finalize failed: ", REASON(), NULL);
	return TCL_ERROR;
    }
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * EncryptDataHandler --
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
int EncryptDataHandler(Tcl_Interp *interp, int type, Tcl_Obj *dataObj, Tcl_Obj *cipherObj,
	Tcl_Obj *digestObj, Tcl_Obj *keyObj, Tcl_Obj *ivObj) {
    EVP_CIPHER_CTX *ctx = NULL;
    int data_len = 0, out_len = 0, res;
    unsigned char *data, *outbuf;
    Tcl_Obj *resultObj;

    dprintf("Called");

    /* Get data */
    if (dataObj != NULL) {
	data = Tcl_GetByteArrayFromObj(dataObj, &data_len);
    } else {
	Tcl_AppendResult(interp, "No data", NULL);
	return TCL_ERROR;
    }

    /* Allocate storage for encrypted data. Size should be data size + block size. */
    resultObj = Tcl_NewObj();
    outbuf = Tcl_SetByteArrayLength(resultObj, data_len+1024);
    if (resultObj == NULL || outbuf == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Perform operation */
    if (EncryptInitialize(interp, type, &ctx, cipherObj, keyObj, ivObj) != TCL_OK ||
	EncryptUpdate(interp, type, ctx, outbuf, &out_len, data, data_len) != TCL_OK ||
	EncryptFinalize(interp, type, ctx, outbuf+out_len, &out_len) != TCL_OK) {
	res = TCL_ERROR;
	goto done;
    }

done:
    /* Set output result */
    if (res == TCL_OK) {
	outbuf = Tcl_SetByteArrayLength(resultObj, out_len);
	Tcl_SetObjResult(interp, resultObj);
    } else {
	Tcl_DecrRefCount(resultObj);
	/* Result is error message */
    }

    /* Clean up */
    if (ctx != NULL) {
	EVP_CIPHER_CTX_free(ctx);
    }
    return res;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * EncryptMain --
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
static int EncryptMain(int type, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int res = TCL_OK;
    Tcl_Obj *cipherObj = NULL, *cmdObj = NULL, *dataObj = NULL, *digestObj = NULL;
    Tcl_Obj *inFileObj = NULL, *outFileObj = NULL, *keyObj = NULL, *ivObj = NULL, *macObj = NULL;
    const char *channel = NULL, *opt;
    const EVP_MD *md = NULL;
    const EVP_CIPHER *cipher = NULL;

    dprintf("Called");

    /* Clear interp result */
    Tcl_ResetResult(interp);

    /* Validate arg count */
    if (objc < 3 || objc > 12) {
	Tcl_WrongNumArgs(interp, 1, objv, "-cipher name ?-digest name? ?-key key? ?-iv string? [-data data]");
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
	res = EncryptDataHandler(interp, type, dataObj, cipherObj, digestObj, keyObj, ivObj);
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
    return EncryptMain(TYPE_ENCRYPT, interp, objc, objv);
}

static int DecryptObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return EncryptMain(TYPE_DECRYPT, interp, objc, objv);
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
    return TCL_OK;
}

