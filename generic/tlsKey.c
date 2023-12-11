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
    int key_len = 0, md_len = 0, pass_len = 0, salt_len = 0;
    int iklen, ivlen, iter = PKCS5_DEFAULT_ITER;
    unsigned char *passwd = NULL, *salt = NULL;
    Tcl_Obj *cipherObj = NULL, *digestObj = NULL, *passwdObj = NULL, *saltObj = NULL, *resultObj;
    const EVP_MD *md = NULL;
    const EVP_CIPHER *cipher = NULL;
    int max = EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH, size = max;
    unsigned char tmpkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];

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
	char *opt = Tcl_GetStringFromObj(objv[idx], NULL);

	if (opt[0] != '-') {
	    break;
	}

	OPTOBJ("-cipher", cipherObj);
	OPTOBJ("-digest", digestObj);
	OPTOBJ("-hash", digestObj);
	OPTINT("-iterations", iter);
	OPTOBJ("-password", passwdObj);
	OPTOBJ("-salt", saltObj);
	OPTINT("-size", size);

	OPTBAD("option", "-cipher, -digest, -iterations, -password, -salt, or -size option");
	return TCL_ERROR;
    }

    /* Validate options */
    if (cipherObj != NULL) {
	char *name = Tcl_GetByteArrayFromObj(cipherObj, NULL);
	cipher = EVP_get_cipherbyname(name);
    }
    if (digestObj != NULL) {
	char *name = Tcl_GetStringFromObj(digestObj, &md_len);
	md = EVP_get_digestbyname(name);
    } else {
	Tcl_AppendResult(interp, "No digest specified", NULL);
	return TCL_ERROR;
    }
    if (passwdObj != NULL) {
	passwd = Tcl_GetByteArrayFromObj(passwdObj, &pass_len);
    }
    if (saltObj != NULL) {
	salt = Tcl_GetByteArrayFromObj(saltObj, &salt_len);
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

