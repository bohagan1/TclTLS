/*
 * Key Derivation Function (KDF) Module
 *
 * Provides commands to derive keys.
 *
 * Copyright (C) 2023 Brian O'Hagan
 *
 */

#include "tlsInt.h"
#include "tclOpts.h"
#include <openssl/crypto.h>

/*******************************************************************/

static const char *command_opts [] = { 
    "-cipher", "-digest", "-hash", "-iterations", "-password", "-salt", "-size", NULL};

enum _command_opts {
    _opt_cipher, _opt_digest, _opt_hash, _opt_iter, _opt_password, _opt_salt, _opt_size
};

/*
 *-------------------------------------------------------------------
 *
 * DeriveKey --
 *
 *	PKCS5_PBKDF2_HMAC key derivation function (KDF) specified by PKCS #5.
 *	See RFC 6070.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to a list of key and iv values, or an error message
 *
 *-------------------------------------------------------------------
 */
static int DeriveKey(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int key_len = 0, md_len = 0, pass_len = 0, salt_len = 0, fn;
    int iklen, ivlen, iter = PKCS5_DEFAULT_ITER;
    unsigned char *passwd = NULL, *salt = NULL;
    Tcl_Obj *resultObj;
    const EVP_MD *md = NULL;
    const EVP_CIPHER *cipher = NULL;
    int max = EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH, size = max;
    unsigned char tmpkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];
    char *cipherName = NULL, *digestName = NULL;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc < 3 || objc > 11) {
	Tcl_WrongNumArgs(interp, 1, objv, "[-cipher cipher | -size length] -digest digest ?-iterations count? ?-password string? ?-salt string?");
	return TCL_ERROR;
    }

    /* Init buffers */
    memset(tmpkeyiv, 0, EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH);

    /* Get options */
    for (int idx = 1; idx < objc; idx++) {
	/* Get option */
	if (Tcl_GetIndexFromObj(interp, objv[idx], command_opts, "option", 0, &fn) != TCL_OK) {
	    return TCL_ERROR;
	}

	/* Validate arg has value */
	if (++idx >= objc) {
	    Tcl_AppendResult(interp, "No value for option \"", command_opts[fn], "\"", (char *) NULL);
	return TCL_ERROR;
    }

	switch(fn) {
	case _opt_cipher:
	    GET_OPT_STRING(objv[idx], cipherName, NULL);
	    break;
	case _opt_digest:
	case _opt_hash:
	    GET_OPT_STRING(objv[idx], digestName, NULL);
	    break;
	case _opt_iter:
	    GET_OPT_INT(objv[idx], &iter);
	    break;
	case _opt_password:
	    GET_OPT_BYTE_ARRAY(objv[idx], passwd, &pass_len);
	    break;
	case _opt_salt:
	    GET_OPT_BYTE_ARRAY(objv[idx], salt, &salt_len);
	    break;
	case _opt_size:
	    GET_OPT_INT(objv[idx], &size);
	    break;
	}
    }

    /* Validate options */
    if (cipherName != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	cipher = EVP_get_cipherbyname(cipherName);
#else
	cipher = EVP_CIPHER_fetch(NULL, cipherName, NULL);
#endif
	if (cipher == NULL) {
	    Tcl_AppendResult(interp, "Invalid cipher: \"", cipherName, "\"", NULL);
	    return TCL_ERROR;
	}
    }
    if (digestName != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	md = EVP_get_digestbyname(digestName);
#else
	md = EVP_MD_fetch(NULL, digestName, NULL);
#endif
	if (md == NULL) {
	    Tcl_AppendResult(interp, "Invalid digest: \"", digestName, "\"", NULL);
	    return TCL_ERROR;
	}
    }
    if (iter < 1) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("Invalid iterations count %d: must be > 0", iter));
	return TCL_ERROR;
    }
    if (size < 1 || size > max) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("Invalid derived key length %d: must be 0 < size <= %d", size, max));
	return TCL_ERROR;
    }

    if (cipher == NULL) {
	if (size > max) size = max;
	iklen = size;
	ivlen = 0;
    } else {
	iklen = EVP_CIPHER_key_length(cipher);
	ivlen = EVP_CIPHER_iv_length(cipher);
	size = iklen+ivlen;
    }

    /* Perform password derivation */
    if (!PKCS5_PBKDF2_HMAC(passwd, pass_len, salt, salt_len, iter, md, size, tmpkeyiv)) {
	Tcl_AppendResult(interp, "Key derivation failed: ", REASON(), NULL);
	return TCL_ERROR;
    }

   /* Return key and iv */
    if (cipher == NULL) {
	resultObj = Tcl_NewByteArrayObj(tmpkeyiv, size);
    } else {
	resultObj = Tcl_NewListObj(0, NULL);
	LAPPEND_BARRAY(interp, resultObj, "key", tmpkeyiv, iklen);
	LAPPEND_BARRAY(interp, resultObj, "iv", tmpkeyiv+iklen, ivlen);
    }
    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
    	clientData = clientData;
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_KeyCommands --
 *
 *	Create key commands
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Creates commands
 *
 *-------------------------------------------------------------------
 */
int Tls_KeyCommands(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tls::derive_key", DeriveKey, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}

