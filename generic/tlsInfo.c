/*
 * Information Commands Module
 *
 * Provides commands that return info related to the OpenSSL config and data.
 *
 * Copyright (C) 2023 Brian O'Hagan
 *
 */

#include "tlsInt.h"
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/safestack.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

/*
 * Valid SSL and TLS Protocol Versions
 */
static const char *protocols[] = {
	"ssl2", "ssl3", "tls1", "tls1.1", "tls1.2", "tls1.3", NULL
};
enum protocol {
    TLS_SSL2, TLS_SSL3, TLS_TLS1, TLS_TLS1_1, TLS_TLS1_2, TLS_TLS1_3, TLS_NONE
};

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * NamesCallback --
 *
 *	Callback to add algorithm or method names to a TCL list object.
 *
 * Results:
 *	Append name to TCL list object.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
void NamesCallback(const OBJ_NAME *obj, void *arg) {
    Tcl_Obj *listObj = (Tcl_Obj *) arg;

    /* Fields: (int) type and alias, (const char*) name (alias from) and data (alias to) */
    if (strstr(obj->name, "rsa") == NULL && strstr(obj->name, "RSA") == NULL) {
	Tcl_ListObjAppendElement(NULL, listObj, Tcl_NewStringObj(obj->name, -1));
    }
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * CipherInfo --
 *
 *	Return a list of properties and values for cipher.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int CipherInfo(Tcl_Interp *interp, Tcl_Obj *nameObj) {
    const EVP_CIPHER *cipher;
    Tcl_Obj *resultObj, *listObj;
    unsigned long flags, mode;
    char *modeName = NULL;
    char *name = Tcl_GetStringFromObj(nameObj, (Tcl_Size *) NULL);

    /* Get cipher */
    cipher = EVP_get_cipherbyname(name);

    if (cipher == NULL) {
	Tcl_AppendResult(interp, "Invalid cipher \"", name, "\"", (char *) NULL);
	return TCL_ERROR;
    }

    /* Get properties */
    resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }
    LAPPEND_STR(interp, resultObj, "nid", OBJ_nid2ln(EVP_CIPHER_nid(cipher)), -1);
    LAPPEND_STR(interp, resultObj, "name", EVP_CIPHER_name(cipher), -1);
    LAPPEND_STR(interp, resultObj, "description", "", -1);
    LAPPEND_INT(interp, resultObj, "block_size", EVP_CIPHER_block_size(cipher));
    LAPPEND_INT(interp, resultObj, "key_length", EVP_CIPHER_key_length(cipher));
    LAPPEND_INT(interp, resultObj, "iv_length", EVP_CIPHER_iv_length(cipher));
    LAPPEND_STR(interp, resultObj, "type", OBJ_nid2ln(EVP_CIPHER_type(cipher)), -1);
    LAPPEND_STR(interp, resultObj, "provider", "", -1);
    flags = EVP_CIPHER_flags(cipher);
    mode  = EVP_CIPHER_mode(cipher);

    /* EVP_CIPHER_get_mode */
    switch(mode) {
	case EVP_CIPH_STREAM_CIPHER:
	    modeName = "STREAM";
	    break;
	case EVP_CIPH_ECB_MODE:
	    modeName = "ECB";
	    break;
	case EVP_CIPH_CBC_MODE:
	    modeName = "CBC";
	    break;
	case EVP_CIPH_CFB_MODE:
	    modeName = "CFB";
	    break;
	case EVP_CIPH_OFB_MODE:
	    modeName = "OFB";
	    break;
	case EVP_CIPH_CTR_MODE:
	    modeName = "CTR";
	    break;
	case EVP_CIPH_GCM_MODE:
	    modeName = "GCM";
	    break;
	case EVP_CIPH_XTS_MODE:
	    modeName = "XTS";
	    break;
	case EVP_CIPH_CCM_MODE:
	    modeName = "CCM";
	    break;
	case EVP_CIPH_OCB_MODE:
	    modeName = "OCB";
	    break;
	case EVP_CIPH_WRAP_MODE :
	    modeName = "WRAP";
	    break;
	default:
	    modeName = "unknown";
	    break;
    }
    LAPPEND_STR(interp, resultObj, "mode", modeName, -1);

    /* Flags */
    listObj = Tcl_NewListObj(0, NULL);
    LAPPEND_BOOL(interp, listObj, "Variable Length", flags & EVP_CIPH_VARIABLE_LENGTH);
    LAPPEND_BOOL(interp, listObj, "Always Call Init", flags & EVP_CIPH_ALWAYS_CALL_INIT);
    LAPPEND_BOOL(interp, listObj, "Custom IV", flags & EVP_CIPH_CUSTOM_IV);
    LAPPEND_BOOL(interp, listObj, "Control Init", flags & EVP_CIPH_CTRL_INIT);
    LAPPEND_BOOL(interp, listObj, "Custom Cipher", flags & EVP_CIPH_FLAG_CUSTOM_CIPHER);
    LAPPEND_BOOL(interp, listObj, "AEAD Cipher", flags & EVP_CIPH_FLAG_AEAD_CIPHER);
    LAPPEND_BOOL(interp, listObj, "Custom Copy", flags & EVP_CIPH_CUSTOM_COPY);
    LAPPEND_BOOL(interp, listObj, "Non FIPS Allow", flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW);
    LAPPEND_OBJ(interp, resultObj, "flags", listObj);

    /* CTX only properties */
    {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int tag_len = 0;

	EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
	if (mode == EVP_CIPH_GCM_MODE || mode == EVP_CIPH_OCB_MODE) {
	    tag_len = EVP_GCM_TLS_TAG_LEN; /* EVP_MAX_AEAD_TAG_LENGTH */
	} else if (mode == EVP_CIPH_CCM_MODE) {
	    tag_len = EVP_CCM_TLS_TAG_LEN;
	} else if (cipher == EVP_get_cipherbyname("chacha20-poly1305")) {
	    tag_len = EVP_CHACHAPOLY_TLS_TAG_LEN; /* POLY1305_BLOCK_SIZE */
	}
	EVP_CIPHER_CTX_free(ctx);
	LAPPEND_INT(interp, resultObj, "tag_length", tag_len);
    }
    
    /* AEAD properties */
    {
	int aad_len = 0;
	if (flags & EVP_CIPH_FLAG_AEAD_CIPHER) {
	    aad_len = EVP_AEAD_TLS1_AAD_LEN;
	}
	LAPPEND_INT(interp, resultObj, "aad_length", aad_len);
    }

    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * CipherList --
 *
 *	Return a list of all cipher algorithms
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int CipherList(Tcl_Interp *interp) {
    Tcl_Obj *resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }

    /* Same as EVP_CIPHER_do_all */
    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, NamesCallback, (void *) resultObj);
    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * CipherObjCmd --
 *
 *	Return a list of properties and values for cipherName.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
static int CipherObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void) clientData;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc == 1) {
	return CipherList(interp);

    } else if (objc == 2) {
	return CipherInfo(interp, objv[1]);

    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?name?");
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * CiphersObjCmd --
 *
 *	This procedure is invoked to process the "tls::ciphers" command
 *	to list available ciphers, based upon protocol selected.
 *
 * Results:
 *	A standard Tcl result list.
 *
 * Side effects:
 *	constructs and destroys SSL context (CTX)
 *
 *-------------------------------------------------------------------
 */
static int CiphersObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *sk = NULL;
    Tcl_Size index;
    int verbose = 0, use_supported = 0, res = TCL_OK;
    int min_version, max_version;
    (void) clientData;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc > 4) {
	Tcl_WrongNumArgs(interp, 1, objv, "?protocol? ?verbose? ?supported?");
	return TCL_ERROR;
    }

    /* List all ciphers */
    if (objc == 1) {
	return CipherList(interp);
    }

    /* Get options */
    if (Tcl_GetIndexFromObj(interp, objv[1], protocols, "protocol", 0, &index) != TCL_OK ||
	(objc > 2 && Tcl_GetBooleanFromObj(interp, objv[2], &verbose) != TCL_OK) ||
	(objc > 3 && Tcl_GetBooleanFromObj(interp, objv[3], &use_supported) != TCL_OK)) {
	return TCL_ERROR;
    }

    switch ((enum protocol)index) {
	case TLS_SSL2:
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *) NULL);
	    return TCL_ERROR;
	case TLS_SSL3:
#if defined(NO_SSL3) || defined(OPENSSL_NO_SSL3) || defined(OPENSSL_NO_SSL3_METHOD)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *) NULL);
	    return TCL_ERROR;
#else
            min_version = SSL3_VERSION;
            max_version = SSL3_VERSION;
	    break;
#endif
	case TLS_TLS1:
#if defined(NO_TLS1) || defined(OPENSSL_NO_TLS1) || defined(OPENSSL_NO_TLS1_METHOD)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *) NULL);
	    return TCL_ERROR;
#else
            min_version = TLS1_VERSION;
            max_version = TLS1_VERSION;
	    break;
#endif
	case TLS_TLS1_1:
#if defined(NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1_METHOD)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *) NULL);
	    return TCL_ERROR;
#else
            min_version = TLS1_1_VERSION;
            max_version = TLS1_1_VERSION;
	    break;
#endif
	case TLS_TLS1_2:
#if defined(NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2_METHOD)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *) NULL);
	    return TCL_ERROR;
#else
            min_version = TLS1_2_VERSION;
            max_version = TLS1_2_VERSION;
	    break;
#endif
	case TLS_TLS1_3:
#if defined(NO_TLS1_3) || defined(OPENSSL_NO_TLS1_3)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", (char *) NULL);
	    return TCL_ERROR;
#else
            min_version = TLS1_3_VERSION;
            max_version = TLS1_3_VERSION;
	    break;
#endif
	default:
            min_version = SSL3_VERSION;
            max_version = TLS1_3_VERSION;
	    break;
    }

    /* Create context */
    if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
	Tcl_AppendResult(interp, GET_ERR_REASON(), (char *) NULL);
	return TCL_ERROR;
    }

    /* Set protocol versions */
    if (SSL_CTX_set_min_proto_version(ctx, min_version) == 0 ||
	SSL_CTX_set_max_proto_version(ctx, max_version) == 0) {
	SSL_CTX_free(ctx);
	return TCL_ERROR;
    }

    /* Create SSL context */
    if ((ssl = SSL_new(ctx)) == NULL) {
	Tcl_AppendResult(interp, GET_ERR_REASON(), (char *) NULL);
	SSL_CTX_free(ctx);
	return TCL_ERROR;
    }

    /* Use list and order as would be sent in a ClientHello or all available ciphers */
    if (use_supported) {
	sk = SSL_get1_supported_ciphers(ssl);
    } else {
	sk = SSL_get_ciphers(ssl);
	/*sk = SSL_CTX_get_ciphers(ctx);*/
    }

    if (sk != NULL) {
	Tcl_Obj *resultObj = NULL;

	if (!verbose) {
	    const char *cp;
	    resultObj = Tcl_NewListObj(0, NULL);
	    if (resultObj == NULL) {
		res = TCL_ERROR;
		goto done;
	    }

	    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c == NULL) continue;

		/* cipher name or (NONE) */
		cp = SSL_CIPHER_get_name(c);
		if (cp == NULL) break;
		Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj((char *) cp, -1));
	    }

	} else {
	    char buf[BUFSIZ];
	    resultObj = Tcl_NewStringObj("", 0);
	    if (resultObj == NULL) {
		res = TCL_ERROR;
		goto done;
	    }

	    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c == NULL) continue;

		/* textual description of the cipher */
		if (SSL_CIPHER_description(c, buf, sizeof(buf)) != NULL) {
		    Tcl_AppendToObj(resultObj, buf, (Tcl_Size) strlen(buf));
		} else {
		    Tcl_AppendToObj(resultObj, "UNKNOWN\n", 8);
		}
	    }
	}

	/* Clean up */
	if (use_supported) {
	    sk_SSL_CIPHER_free(sk);
	}
	Tcl_SetObjResult(interp, resultObj);
    }

done:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return res;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestInfo --
 *
 *	Return a list of properties and values for digest.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int DigestInfo(Tcl_Interp *interp, Tcl_Obj *nameObj) {
    const EVP_MD *md;
    Tcl_Obj *resultObj, *listObj;
    unsigned long flags;
    char *name = Tcl_GetStringFromObj(nameObj, (Tcl_Size *) NULL);

    /* Get message digest */
    md = EVP_get_digestbyname(name);

    if (md == NULL) {
	Tcl_AppendResult(interp, "Invalid digest \"", name, "\"", (char *) NULL);
	return TCL_ERROR;
    }

    /* Get properties */
    resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }
    LAPPEND_STR(interp, resultObj, "name", EVP_MD_name(md), -1);
    LAPPEND_STR(interp, resultObj, "description", "", -1);
    LAPPEND_INT(interp, resultObj, "size", EVP_MD_size(md));
    LAPPEND_INT(interp, resultObj, "block_size", EVP_MD_block_size(md));
    LAPPEND_STR(interp, resultObj, "provider", "", -1);
    LAPPEND_STR(interp, resultObj, "type", OBJ_nid2ln(EVP_MD_type(md)), -1);
    LAPPEND_STR(interp, resultObj, "pkey_type", OBJ_nid2ln(EVP_MD_pkey_type(md)), -1);
    flags = EVP_MD_flags(md);

    /* Flags */
    listObj = Tcl_NewListObj(0, NULL);
    LAPPEND_BOOL(interp, listObj, "One-shot", flags & EVP_MD_FLAG_ONESHOT);
    LAPPEND_BOOL(interp, listObj, "XOF", flags & EVP_MD_FLAG_XOF);
    LAPPEND_BOOL(interp, listObj, "DigestAlgorithmId_NULL", flags & EVP_MD_FLAG_DIGALGID_NULL);
    LAPPEND_BOOL(interp, listObj, "DigestAlgorithmId_Abscent", flags & EVP_MD_FLAG_DIGALGID_ABSENT);
    LAPPEND_BOOL(interp, listObj, "DigestAlgorithmId_Custom", flags & EVP_MD_FLAG_DIGALGID_CUSTOM);
    LAPPEND_BOOL(interp, listObj, "FIPS", flags & EVP_MD_FLAG_FIPS);
    LAPPEND_OBJ(interp, resultObj, "flags", listObj);

    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * DigestList --
 *
 *	Return a list of all digest algorithms
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int DigestList(Tcl_Interp *interp) {
    Tcl_Obj *resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }

    /* Same as EVP_MD_do_all */
    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, NamesCallback, (void *) resultObj);
    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * DigestsObjCmd --
 *
 *	Return a list of all valid hash algorithms or message digests.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int DigestsObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void) clientData;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();


    /* Validate arg count */
    if (objc == 1) {
	return DigestList(interp);

    } else if (objc == 2) {
	return DigestInfo(interp, objv[1]);

    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?name?");
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * KdfList --
 *
 *	Return a list of all KDF algorithms
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int KdfList(Tcl_Interp *interp, char *select_name) {
    Tcl_Obj *resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }

    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj("hkdf", -1));
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj("pbkdf2", -1));
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj("scrypt", -1));
    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * KdfsObjCmd --
 *
 *	Return a list of all valid Key Derivation Function (KDF).
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int KdfsObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void) clientData;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();


    /* Validate arg count */
    if (objc == 1) {
	return KdfList(interp, NULL);

    } else if (objc == 2) {


    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?name?");
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * MacInfo --
 *
 *	Return a list of properties and values for macName.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int MacInfo(Tcl_Interp *interp, Tcl_Obj *nameObj) {
    Tcl_Obj *resultObj;
    int res = TCL_OK;
    char *name = Tcl_GetStringFromObj(nameObj, (Tcl_Size *) NULL);

    if (strcmp(name, "cmac") != 0 && strcmp(name, "hmac") != 0) {
	Tcl_AppendResult(interp, "Invalid MAC \"", name, "\"", (char *) NULL);
	return TCL_ERROR;
    }

    /* Get properties */
    resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }
    LAPPEND_STR(interp, resultObj, "name", name, -1);
    LAPPEND_STR(interp, resultObj, "description", "", -1);
    LAPPEND_STR(interp, resultObj, "provider", "", -1);

    Tcl_SetObjResult(interp, resultObj);
    return res;
}

/*
 *-------------------------------------------------------------------
 *
 * MacList --
 *
 *	Return a list of all MAC algorithms
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int MacList(Tcl_Interp *interp) {
    Tcl_Obj *resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }

    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj("cmac", -1));
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj("hmac", -1));
    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * MacsObjCmd --
 *
 *	Return a list of all valid message authentication codes (MAC).
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int MacsObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void) clientData;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc == 1) {
	return MacList(interp);

    } else if (objc == 2) {
	return MacInfo(interp, objv[1]);

    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?name?");
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * PkeyInfo --
 *
 *	Return a list of properties and values for pkey.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int PkeyInfo(Tcl_Interp *interp, Tcl_Obj *nameObj) {
    Tcl_Obj *resultObj;
    int res = TCL_OK;
    char *name = Tcl_GetStringFromObj(nameObj, (Tcl_Size *) NULL);
    EVP_PKEY *pkey = NULL;

    if (pkey == NULL) {
	Tcl_AppendResult(interp, "Invalid public key method \"", name, "\"", (char *) NULL);
	return TCL_ERROR;
    }

    /* Get properties */
    resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }
    LAPPEND_STR(interp, resultObj, "name", OBJ_nid2ln(EVP_PKEY_id(pkey)), -1);
    LAPPEND_STR(interp, resultObj, "description", "", -1);
    LAPPEND_INT(interp, resultObj, "size", EVP_PKEY_size(pkey));
    LAPPEND_INT(interp, resultObj, "bits", EVP_PKEY_bits(pkey));
    LAPPEND_INT(interp, resultObj, "security_bits", EVP_PKEY_security_bits(pkey));
    LAPPEND_STR(interp, resultObj, "baseId", OBJ_nid2ln(EVP_PKEY_base_id(pkey)), -1);
    LAPPEND_STR(interp, resultObj, "provider", "", -1);
    LAPPEND_STR(interp, resultObj, "type", OBJ_nid2ln(EVP_PKEY_type(EVP_PKEY_id(pkey))), -1);

    {
	int pnid;
	if (EVP_PKEY_get_default_digest_nid(pkey, &pnid) > 0) {
	    LAPPEND_STR(interp, resultObj, "default_digest", OBJ_nid2ln(pnid), -2);
	}
    }

    Tcl_SetObjResult(interp, resultObj);
    return res;
}

/*
 *-------------------------------------------------------------------
 *
 * PkeyList --
 *
 *	Return a list of all public key methods
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int PkeyList(Tcl_Interp *interp) {
    Tcl_Obj *resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }

    for (size_t i = 0; i < EVP_PKEY_meth_get_count(); i++) {
        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_get0(i);
        int pkey_id, pkey_flags;

        EVP_PKEY_meth_get0_info(&pkey_id, &pkey_flags, pmeth);
	/*LAPPEND_STR(interp, resultObj, "name", OBJ_nid2ln(pkey_id), -1);
	LAPPEND_STR(interp, resultObj, "type", pkey_flags & ASN1_PKEY_DYNAMIC ? "External" : "Built-in", -1);*/

	Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj(OBJ_nid2ln(pkey_id), -1));
    }
    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * PkeysObjCmd --
 *
 *	Return a list of all valid hash algorithms or message digests.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int PkeysObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void) clientData;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc == 1) {
	return PkeyList(interp);

    } else if (objc == 2) {
	return PkeyInfo(interp, objv[1]);

    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?name?");
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * ProtocolsObjCmd --
 *
 *	Return a list of the available or supported SSL/TLS protocols.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	none
 *
 *-------------------------------------------------------------------
 */
static int
ProtocolsObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Obj *resultObj;
    (void) clientData;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }

    /* List all protocols */
    resultObj = Tcl_NewListObj(0, NULL);
    if (resultObj == NULL) {
	return TCL_ERROR;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(NO_SSL2) && !defined(OPENSSL_NO_SSL2)
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj(protocols[TLS_SSL2], -1));
#endif
#if !defined(NO_SSL3) && !defined(OPENSSL_NO_SSL3) && !defined(OPENSSL_NO_SSL3_METHOD)
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj(protocols[TLS_SSL3], -1));
#endif
#if !defined(NO_TLS1) && !defined(OPENSSL_NO_TLS1) && !defined(OPENSSL_NO_TLS1_METHOD)
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj(protocols[TLS_TLS1], -1));
#endif
#if !defined(NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1_METHOD)
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj(protocols[TLS_TLS1_1], -1));
#endif
#if !defined(NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2_METHOD)
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj(protocols[TLS_TLS1_2], -1));
#endif
#if !defined(NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3)
    Tcl_ListObjAppendElement(interp, resultObj, Tcl_NewStringObj(protocols[TLS_TLS1_3], -1));
#endif
    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * ProviderObjCmd --
 *
 *	Load a provider.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
static int
ProviderObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    char *name;
    (void) clientData;

    dprintf("Called");

    /* Validate arg count */
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "name");
	return TCL_ERROR;
    }

    name = Tcl_GetStringFromObj(objv[1], NULL);
    if (!OSSL_PROVIDER_try_load(NULL, (const char *) name, 1)) {
	Tcl_AppendResult(interp, GET_ERR_REASON(), (char *) NULL);
	return TCL_ERROR;
    }

    return TCL_OK;
}
#endif

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * VersionObjCmd --
 *
 *	Return a string with the OpenSSL version info.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
static int
VersionObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Obj *resultObj;
    (void) clientData;

    dprintf("Called");

    /* Validate arg count */
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }

    resultObj = Tcl_NewStringObj(OPENSSL_VERSION_TEXT, -1);
    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * Tls_InfoCommands --
 *
 *	Create info commands
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Creates commands
 *
 *-------------------------------------------------------------------
 */
int Tls_InfoCommands(Tcl_Interp *interp) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();
#endif

    Tcl_CreateObjCommand(interp, "tls::cipher", CipherObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::ciphers", CiphersObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::digests", DigestsObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::kdfs", KdfsObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::macs", MacsObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::pkeys", PkeysObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::protocols", ProtocolsObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    Tcl_CreateObjCommand(interp, "tls::provider", ProviderObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
#endif
    Tcl_CreateObjCommand(interp, "tls::version", VersionObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}

