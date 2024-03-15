/*
 * Cryptographic Utility Functions
 *
 * Provides commands to derive keys.
 *
 * Copyright (C) 2023 Brian O'Hagan
 *
 */

#include "tlsInt.h"
#include "tclOpts.h"
#include <openssl/evp.h>


/*
 *-------------------------------------------------------------------
 *
 * Util_GetCipher --
 *
 *	Get symmetric cipher from TclObj
 *
 * Returns:
 *	Pointer to type or NULL
 *
 * Side effects:
 *	None
 *
 *-------------------------------------------------------------------
 */
EVP_CIPHER *Util_GetCipher(Tcl_Interp *interp, Tcl_Obj *cipherObj, int no_null) {
    EVP_CIPHER *cipher = NULL;
    char *name = NULL;

    if (cipherObj != NULL) {
	name = Tcl_GetString(cipherObj);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	cipher = EVP_get_cipherbyname(name);
#else
	cipher = EVP_CIPHER_fetch(NULL, name, NULL);
#endif
	if (cipher == NULL) {
	    Tcl_AppendResult(interp, "invalid cipher \"", name, "\"", (char *) NULL);
	}
    } else if (no_null) {
	Tcl_AppendResult(interp, "no cipher", (char *) NULL);
    }
    return cipher;
}

/*
 *-------------------------------------------------------------------
 *
 * Util_GetDigest --
 *
 *	Get message digest (MD) or hash from TclObj
 *
 * Returns:
 *	Pointer to type or NULL
 *
 * Side effects:
 *	None
 *
 *-------------------------------------------------------------------
 */
EVP_MD *Util_GetDigest(Tcl_Interp *interp, Tcl_Obj *digestObj, int no_null) {
    EVP_MD *md = NULL;
    char *name = NULL;

    if (digestObj != NULL) {
	name = Tcl_GetString(digestObj);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	md = EVP_get_digestbyname(name);
#else
	md = EVP_MD_fetch(NULL, name, NULL);
#endif
	if (md == NULL) {
	    Tcl_AppendResult(interp, "invalid digest \"", name, "\"", (char *) NULL);
	}
    } else if (no_null) {
	Tcl_AppendResult(interp, "no digest", (char *) NULL);
    }
    return md;
}

/*
 *-------------------------------------------------------------------
 *
 * Util_GetIV --
 *
 *	Get encryption initialization vector or seed from TclObj
 *
 * Returns:
 *	Pointer to type or NULL, and size
 *
 * Side effects:
 *	None
 *
 *-------------------------------------------------------------------
 */
unsigned char *Util_GetIV(Tcl_Interp *interp, Tcl_Obj *ivObj, Tcl_Size *len, int max, int no_null) {
    unsigned char *iv = NULL;
    *len = 0;
    Tcl_Size size = 0;

    if (ivObj != NULL) {
	iv = Tcl_GetByteArrayFromObj(ivObj, &size);
	*len = (int) size;
    } else if (no_null) {
	Tcl_AppendResult(interp, "no initialization vector (IV)", (char *) NULL);
	return NULL;
    }

    if (max > 0 && *len > max) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("IV too long. Must be <= %d bytes", max));
	return NULL;
    }
    return iv;
}

/*
 *-------------------------------------------------------------------
 *
 * Util_GetKey --
 *
 *	Get encryption key or password from TclObj
 *
 * Returns:
 *	Pointer to type or NULL, and size
 *
 * Side effects:
 *	None
 *
 *-------------------------------------------------------------------
 */
unsigned char *Util_GetKey(Tcl_Interp *interp, Tcl_Obj *keyObj, Tcl_Size *len, char *name, int max, int no_null) {
    unsigned char *key = NULL;
    *len = 0;

    if (keyObj != NULL) {
	key = Tcl_GetByteArrayFromObj(keyObj, len);
    } else if (no_null) {
	Tcl_AppendResult(interp, "no ", name, (char *) NULL);
	return NULL;
    }

    if (max > 0 && *len > max) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("Invalid %s length. Must be <= %d bytes", name, max));
	return NULL;
    }
    return key;
}

/*
 *-------------------------------------------------------------------
 *
 * Util_GetMAC --
 *
 *	Get Message Authentication Code (MAC) from TclObj
 *
 * Returns:
 *	Pointer to type or NULL
 *
 * Side effects:
 *	None
 *
 *-------------------------------------------------------------------
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
EVP_MAC *Util_GetMAC(Tcl_Interp *interp, Tcl_Obj *MacObj, int no_null) {
    EVP_MAC *mac = NULL;
    char *name = NULL;

    if (MacObj != NULL) {
	name = Tcl_GetString(MacObj);
	mac = EVP_MAC_fetch(NULL, name, NULL);
	if (mac == NULL) {
	    Tcl_AppendResult(interp, "invalid MAC \"", name, "\"", (char *) NULL);
	    return NULL;
	}
    } else if (no_null) {
	Tcl_AppendResult(interp, "no MAC", (char *) NULL);
    }
    return mac;
}
#endif

/*
 *-------------------------------------------------------------------
 *
 * Util_GetSalt --
 *
 *	Get encryption salt from TclObj
 *
 * Returns:
 *	Pointer to type or NULL, and size
 *
 * Side effects:
 *	None
 *
 *-------------------------------------------------------------------
 */
unsigned char *Util_GetSalt(Tcl_Interp *interp, Tcl_Obj *saltObj, Tcl_Size *len, int max, int no_null) {
    unsigned char *salt = NULL;
    *len = 0;

    if (saltObj != NULL) {
	salt = Tcl_GetByteArrayFromObj(saltObj, len);
    } else if (no_null) {
	Tcl_AppendResult(interp, "no salt", (char *) NULL);
	return NULL;
    }

    if (max > 0 && *len > max) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("Salt too long. Must be <= %d bytes", max));
	return NULL;
    }
    return salt;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * Util_GetBinaryArray --
 *
 *	Get binary array from TclObj
 *
 * Returns:
 *	Pointer to type or NULL, and size
 *
 * Side effects:
 *	None
 *
 *-------------------------------------------------------------------
 */
unsigned char *Util_GetBinaryArray(Tcl_Interp *interp, Tcl_Obj *dataObj, Tcl_Size *len,
	char *name, Tcl_Size min, Tcl_Size max, int no_null) {
    unsigned char *data = NULL;
    *len = 0;

    if (dataObj != NULL) {
	data = Tcl_GetByteArrayFromObj(dataObj, len);
    } else if (no_null) {
	Tcl_AppendResult(interp, "no ", name, (char *) NULL);
	return NULL;
    }

    if (*len < min) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("Invalid length for \"%s\": must be >= %" TCL_SIZE_MODIFIER "d", name, min));
	return NULL;
    } else if (max > 0 && *len > max) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("Invalid length for \"%s\": must be <= %" TCL_SIZE_MODIFIER "d", name, max));
	return NULL;
    }
    return data;
}

/*
 *-------------------------------------------------------------------
 *
 * Util_GetInt --
 *
 *	Get integer value from TclObj
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	None
 *
 *-------------------------------------------------------------------
 */

int Util_GetInt(Tcl_Interp *interp, Tcl_Obj *dataObj, int *value, char *name, int min, int max) {

    if (dataObj != NULL) {
	if (Tcl_GetIntFromObj(interp, dataObj, value) != TCL_OK) {
	    return TCL_ERROR;
	}
    }

    /* Validate range */
    if (*value < min) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("invalid value \"%d\" for option \"%s\": must be >= %d", *value, name, min));
	return TCL_ERROR;
    } else if (max > 0 && *value > max) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("invalid value \"%d\" for option \"%s\": must be <= %d", *value, name, max));
	return TCL_ERROR;
    }
    return TCL_OK;
}

