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
#include <openssl/evp.h>
#include <openssl/kdf.h>

/*******************************************************************/

/*
 * Get cipher
 */
EVP_CIPHER *Util_GetCipher(Tcl_Interp *interp, char *name, int exist) {
    EVP_CIPHER *cipher = NULL;

    if (name != NULL) {
	cipher = EVP_get_cipherbyname(name);
	if (cipher == NULL) {
	    Tcl_AppendResult(interp, "Invalid cipher: \"", name, "\"", NULL);
	}
    } else if (exist) {
	Tcl_AppendResult(interp, "No cipher specified", NULL);
    }
    return cipher;
}

/*
 * Get message digest
 */
EVP_MD *Util_GetDigest(Tcl_Interp *interp, char *name, int exist) {
    EVP_MD *md = NULL;

    if (name != NULL) {
	md = EVP_get_digestbyname(name);
	if (md == NULL) {
	    Tcl_AppendResult(interp, "Invalid digest: \"", name, "\"", NULL);
	}
    } else if (exist) {
	Tcl_AppendResult(interp, "No digest specified", NULL);
    }
    return md;
}

/*******************************************************************/

/* Options for KDF commands */

static const char *command_opts [] = {
    "-cipher", "-digest", "-hash", "-info", "-iterations", "-key", "-length", "-password",
    "-salt", "-size", "-N", "-n", "-r", "-p", NULL};

enum _command_opts {
    _opt_cipher, _opt_digest, _opt_hash, _opt_info, _opt_iter, _opt_key, _opt_length,
    _opt_password, _opt_salt, _opt_size, _opt_N, _opt_n, _opt_r, _opt_p
};

/*
 *-------------------------------------------------------------------
 *
 * KDF_PBKDF2 --
 *
 *	PKCS5_PBKDF2_HMAC key derivation function (KDF) specified by PKCS #5.
 *	KDFs include PBKDF2 from RFC 2898/8018 and Scrypt from RFC 7914.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to a list of key and iv values, or an error message
 *
 *-------------------------------------------------------------------
 */
static int KDF_PBKDF2(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int pass_len = 0, salt_len = 0, fn;
    int iklen, ivlen, iter = 1;
    unsigned char *password = NULL, *salt = NULL;
    const EVP_MD *md = NULL;
    const EVP_CIPHER *cipher = NULL;
    int buf_len = (EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH)*4, dk_len = buf_len;
    unsigned char tmpkeyiv[(EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH)*4];
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
    memset(tmpkeyiv, 0, buf_len);

    /* Get options */
    for (int idx = 1; idx < objc; idx++) {
	/* Get option */
	if (Tcl_GetIndexFromObj(interp, objv[idx], command_opts, "option", 0, &fn) != TCL_OK) {
	    return TCL_ERROR;
	}

	/* Validate arg has a value */
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
	case _opt_key:
	case _opt_password:
	    GET_OPT_BYTE_ARRAY(objv[idx], password, &pass_len);
	    break;
	case _opt_salt:
	    GET_OPT_BYTE_ARRAY(objv[idx], salt, &salt_len);
	    break;
	case _opt_length:
	case _opt_size:
	    GET_OPT_INT(objv[idx], &dk_len);
	    break;
	}
    }

    /* Validate options */
    if (cipherName != NULL && (cipher = Util_GetCipher(interp, cipherName, 0)) == NULL) {
	return TCL_ERROR;
    }

    if ((md = Util_GetDigest(interp, digestName, TRUE)) == NULL) {
	return TCL_ERROR;
    }

    if (iter < 1) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("Invalid iterations count %d: must be > 0", iter));
	return TCL_ERROR;
    }

    if (dk_len < 1 || dk_len > buf_len) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("Invalid derived key length %d: must be 0 < size <= %d", dk_len, buf_len));
	return TCL_ERROR;
    }

    /* Set output type sizes */
    if (cipher == NULL) {
	if (dk_len > buf_len) dk_len = buf_len;
	iklen = dk_len;
	ivlen = 0;
    } else {
	iklen = EVP_CIPHER_key_length(cipher);
	ivlen = EVP_CIPHER_iv_length(cipher);
	dk_len = iklen+ivlen;
    }

    /* Derive key */
    if (!PKCS5_PBKDF2_HMAC(password, pass_len, salt, salt_len, iter, md, dk_len, tmpkeyiv)) {
	Tcl_AppendResult(interp, "Key derivation failed: ", REASON(), NULL);
	return TCL_ERROR;
    }

   /* Set result to key and iv */
    if (cipher == NULL) {
	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(tmpkeyiv, dk_len));
    } else {
	Tcl_Obj *resultObj = Tcl_NewListObj(0, NULL);
	LAPPEND_BARRAY(interp, resultObj, "key", tmpkeyiv, iklen);
	LAPPEND_BARRAY(interp, resultObj, "iv", tmpkeyiv+iklen, ivlen);
	Tcl_SetObjResult(interp, resultObj);
    }

    /* Clear data */
    memset(tmpkeyiv, 0, buf_len);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * KDF_HKDF --
 *
 *	HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
 *	See RFC 5869.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to a key of specified length, or an error message
 *
 *-------------------------------------------------------------------
 */
static int KDF_HKDF(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    EVP_PKEY_CTX *pctx;
    const EVP_MD *md = NULL;
    unsigned char *salt = NULL, *key = NULL, *info = NULL, *out = NULL;
    int salt_len = 0, key_len = 0, info_len = 0, dk_len = 1024, res = TCL_OK, fn;
    char *digestName;
    size_t out_len;
    Tcl_Obj *resultObj;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc < 3 || objc > 11) {
	Tcl_WrongNumArgs(interp, 1, objv, "-digest digest -key string ?-info string? ?-salt string? ?-size derived_length?");
	return TCL_ERROR;
    }

    /* Get options */
    for (int idx = 1; idx < objc; idx++) {
	/* Get option */
	if (Tcl_GetIndexFromObj(interp, objv[idx], command_opts, "option", 0, &fn) != TCL_OK) {
	    return TCL_ERROR;
	}

	/* Validate arg has a value */
	if (++idx >= objc) {
	    Tcl_AppendResult(interp, "No value for option \"", command_opts[fn], "\"", (char *) NULL);
	    return TCL_ERROR;
	}

	switch(fn) {
	case _opt_digest:
	case _opt_hash:
	    GET_OPT_STRING(objv[idx], digestName, NULL);
	    break;
	case _opt_info:
	    /* Max 1024/2048 */
	    GET_OPT_BYTE_ARRAY(objv[idx], info, &info_len);
	    break;
	case _opt_key:
	case _opt_password:
	    GET_OPT_BYTE_ARRAY(objv[idx], key, &key_len);
	    break;
	case _opt_salt:
	    GET_OPT_BYTE_ARRAY(objv[idx], salt, &salt_len);
	    break;
	case _opt_length:
	case _opt_size:
	    GET_OPT_INT(objv[idx], &dk_len);
	    break;
	}
    }

    /* Get digest */
    if ((md = Util_GetDigest(interp, digestName, TRUE)) == NULL) {
	goto error;
    }

    /* Create context */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	goto error;
    }

    if (EVP_PKEY_derive_init(pctx) < 1) {
	Tcl_AppendResult(interp, "Initialize failed: ", REASON(), NULL);
	goto error;
    }

    /* Set config parameters */
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) < 1) {
	Tcl_AppendResult(interp, "Set digest failed: ", REASON(), NULL);
	goto error;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) < 1) {
	Tcl_AppendResult(interp, "Set key failed: ", REASON(), NULL);
	goto error;
    }
    if (salt != NULL && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) < 1) {
	Tcl_AppendResult(interp, "Set salt failed: ", REASON(), NULL);
	goto error;
    }
    if (info != NULL && EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) < 1) {
	Tcl_AppendResult(interp, "Set info failed: ", REASON(), NULL);
	goto error;
    }

    /* Get buffer */
    resultObj = Tcl_NewObj();
    if ((out = Tcl_SetByteArrayLength(resultObj, dk_len)) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	goto error;
    }
    out_len = (size_t) dk_len;

    /* Derive key */
    if (EVP_PKEY_derive(pctx, out, &out_len) > 0) {
	/* Shrink buffer to actual size */
	Tcl_SetByteArrayLength(resultObj, (int) out_len);
	Tcl_SetObjResult(interp, resultObj);
	goto done;
    } else {
	Tcl_AppendResult(interp, "Derive key failed: ", REASON(), NULL);
	Tcl_DecrRefCount(resultObj);
    }

error:
    res = TCL_ERROR;
done:
    if (pctx != NULL) {
	EVP_PKEY_CTX_free(pctx);
    }
    return TCL_OK;
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
    Tcl_CreateObjCommand(interp, "tls::hkdf", KDF_HKDF, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::pbkdf2", KDF_PBKDF2, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}

