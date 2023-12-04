/*
 * Information Commands Module
 *
 * Provides commands that return info related to the OpenSSL config and data.
 *
 * Copyright (C) 2023 Brian O'Hagan
 *
 */

#include "tlsInt.h"
#include "tclOpts.h"
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/safestack.h>

/*
 * Valid SSL and TLS Protocol Versions
 */
static const char *protocols[] = {
	"ssl2", "ssl3", "tls1", "tls1.1", "tls1.2", "tls1.3", NULL
};
enum protocol {
    TLS_SSL2, TLS_SSL3, TLS_TLS1, TLS_TLS1_1, TLS_TLS1_2, TLS_TLS1_3, TLS_NONE
};


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
    Tcl_Obj *objPtr = (Tcl_Obj *) arg;

    /* Fields: (int) type and alias, (const char*) name (alias from) and data (alias to) */
    if (strstr(obj->name, "rsa") == NULL && strstr(obj->name, "RSA") == NULL) {
	Tcl_ListObjAppendElement(NULL, objPtr, Tcl_NewStringObj(obj->name,-1));
    }
}

/*******************************************************************/

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
    Tcl_Obj *objPtr, *listPtr;
    unsigned char *cipherName = NULL, *modeName = NULL;
    const EVP_CIPHER *cipher;
    unsigned long flags, mode;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "name");
	return TCL_ERROR;
    }

    /* Get cipher */
    cipherName = Tcl_GetStringFromObj(objv[1], NULL);
    cipher = EVP_get_cipherbyname(cipherName);

    if (cipher == NULL) {
	Tcl_AppendResult(interp, "Invalid cipher \"", cipherName, "\"", NULL);
	return TCL_ERROR;
    }

    /* Get properties */
    objPtr = Tcl_NewListObj(0, NULL);
    if (objPtr == NULL) {
	return TCL_ERROR;
    }
    LAPPEND_STR(interp, objPtr, "nid", OBJ_nid2ln(EVP_CIPHER_nid(cipher)), -1);
    LAPPEND_STR(interp, objPtr, "name", EVP_CIPHER_name(cipher), -1);
    LAPPEND_STR(interp, objPtr, "description", "", -1);
    LAPPEND_INT(interp, objPtr, "block_size", EVP_CIPHER_block_size(cipher));
    LAPPEND_INT(interp, objPtr, "key_length", EVP_CIPHER_key_length(cipher));
    LAPPEND_INT(interp, objPtr, "iv_length", EVP_CIPHER_iv_length(cipher));
    LAPPEND_STR(interp, objPtr, "type", OBJ_nid2ln(EVP_CIPHER_type(cipher)), -1);
    LAPPEND_STR(interp, objPtr, "provider", "", -1);
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
    LAPPEND_STR(interp, objPtr, "mode", modeName, -1);

    /* Flags */
    listPtr = Tcl_NewListObj(0, NULL);
    LAPPEND_BOOL(interp, listPtr, "Variable Length", flags & EVP_CIPH_VARIABLE_LENGTH);
    LAPPEND_BOOL(interp, listPtr, "Always Call Init", flags & EVP_CIPH_ALWAYS_CALL_INIT);
    LAPPEND_BOOL(interp, listPtr, "Custom IV", flags & EVP_CIPH_CUSTOM_IV);
    LAPPEND_BOOL(interp, listPtr, "Control Init", flags & EVP_CIPH_CTRL_INIT);
    LAPPEND_BOOL(interp, listPtr, "Custom Cipher", flags & EVP_CIPH_FLAG_CUSTOM_CIPHER);
    LAPPEND_BOOL(interp, listPtr, "AEAD Cipher", flags & EVP_CIPH_FLAG_AEAD_CIPHER);
    LAPPEND_BOOL(interp, listPtr, "Custom Copy", flags & EVP_CIPH_CUSTOM_COPY);
    LAPPEND_BOOL(interp, listPtr, "Non FIPS Allow", flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW);
    LAPPEND_OBJ(interp, objPtr, "flags", listPtr);

    Tcl_SetObjResult(interp, objPtr);
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
    Tcl_Obj *objPtr = Tcl_NewListObj(0, NULL);
    if (objPtr == NULL) {
	return TCL_ERROR;
    }

    OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, NamesCallback, (void *) objPtr);
    Tcl_SetObjResult(interp, objPtr);
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
    int index, verbose = 0, use_supported = 0, res = TCL_OK;
    int min_version, max_version;

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
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", NULL);
	    return TCL_ERROR;
	case TLS_SSL3:
#if defined(NO_SSL3) || defined(OPENSSL_NO_SSL3) || defined(OPENSSL_NO_SSL3_METHOD)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", NULL);
	    return TCL_ERROR;
#else
            min_version = SSL3_VERSION;
            max_version = SSL3_VERSION;
	    break;
#endif
	case TLS_TLS1:
#if defined(NO_TLS1) || defined(OPENSSL_NO_TLS1) || defined(OPENSSL_NO_TLS1_METHOD)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", NULL);
	    return TCL_ERROR;
#else
            min_version = TLS1_VERSION;
            max_version = TLS1_VERSION;
	    break;
#endif
	case TLS_TLS1_1:
#if defined(NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1_METHOD)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", NULL);
	    return TCL_ERROR;
#else
            min_version = TLS1_1_VERSION;
            max_version = TLS1_1_VERSION;
	    break;
#endif
	case TLS_TLS1_2:
#if defined(NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2_METHOD)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", NULL);
	    return TCL_ERROR;
#else
            min_version = TLS1_2_VERSION;
            max_version = TLS1_2_VERSION;
	    break;
#endif
	case TLS_TLS1_3:
#if defined(NO_TLS1_3) || defined(OPENSSL_NO_TLS1_3)
	    Tcl_AppendResult(interp, protocols[index], ": protocol not supported", NULL);
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
	Tcl_AppendResult(interp, REASON(), NULL);
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
	Tcl_AppendResult(interp, REASON(), NULL);
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
	Tcl_Obj *objPtr = NULL;

	if (!verbose) {
	    char *cp;
	    objPtr = Tcl_NewListObj(0, NULL);
	    if (objPtr == NULL) {
		res = TCL_ERROR;
		goto done;
	    }

	    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c == NULL) continue;

		/* cipher name or (NONE) */
		cp = SSL_CIPHER_get_name(c);
		if (cp == NULL) break;
		Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj(cp, -1));
	    }

	} else {
	    char buf[BUFSIZ];
	    objPtr = Tcl_NewStringObj("",0);
	    if (objPtr == NULL) {
		res = TCL_ERROR;
		goto done;
	    }

	    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c == NULL) continue;

		/* textual description of the cipher */
		if (SSL_CIPHER_description(c, buf, sizeof(buf)) != NULL) {
		    Tcl_AppendToObj(objPtr, buf, (Tcl_Size) strlen(buf));
		} else {
		    Tcl_AppendToObj(objPtr, "UNKNOWN\n", 8);
		}
	    }
	}

	/* Clean up */
	if (use_supported) {
	    sk_SSL_CIPHER_free(sk);
	}
	Tcl_SetObjResult(interp, objPtr);
    }

done:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return res;
	clientData = clientData;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestInfo --
 *
 *	Return a list of properties and values for digestName.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int DigestInfo(Tcl_Interp *interp, char *digestName) {
    Tcl_Obj *objPtr, *listPtr;
    EVP_MD *md = EVP_get_digestbyname(digestName);
    unsigned long flags;

    if (md == NULL) {
	Tcl_AppendResult(interp, "Invalid digest \"", digestName, "\"", NULL);
	return TCL_ERROR;
    }

    /* Get properties */
    objPtr = Tcl_NewListObj(0, NULL);
    if (objPtr == NULL) {
	return TCL_ERROR;
    }
    LAPPEND_STR(interp, objPtr, "name", EVP_MD_name(md), -1);
    LAPPEND_STR(interp, objPtr, "description", "", -1);
    LAPPEND_INT(interp, objPtr, "size", EVP_MD_size(md));
    LAPPEND_INT(interp, objPtr, "block_size", EVP_MD_block_size(md));
    LAPPEND_STR(interp, objPtr, "provider", "", -1);
    LAPPEND_STR(interp, objPtr, "type", OBJ_nid2ln(EVP_MD_type(md)), -1);
    LAPPEND_STR(interp, objPtr, "pkey_type", OBJ_nid2ln(EVP_MD_pkey_type(md)), -1);
    flags = EVP_MD_flags(md);

    /* Flags */
    listPtr = Tcl_NewListObj(0, NULL);
    LAPPEND_BOOL(interp, listPtr, "One-shot", flags & EVP_MD_FLAG_ONESHOT);
    LAPPEND_BOOL(interp, listPtr, "XOF", flags & EVP_MD_FLAG_XOF);
    LAPPEND_BOOL(interp, listPtr, "DigestAlgorithmId_NULL", flags & EVP_MD_FLAG_DIGALGID_NULL);
    LAPPEND_BOOL(interp, listPtr, "DigestAlgorithmId_Abscent", flags & EVP_MD_FLAG_DIGALGID_ABSENT);
    LAPPEND_BOOL(interp, listPtr, "DigestAlgorithmId_Custom", flags & EVP_MD_FLAG_DIGALGID_CUSTOM);
    LAPPEND_BOOL(interp, listPtr, "FIPS", flags & EVP_MD_FLAG_FIPS);
    LAPPEND_OBJ(interp, objPtr, "flags", listPtr);

    Tcl_SetObjResult(interp, objPtr);
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
    Tcl_Obj *objPtr = Tcl_NewListObj(0, NULL);
    if (objPtr == NULL) {
	return TCL_ERROR;
    }

    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, NamesCallback, (void *) objPtr);
    Tcl_SetObjResult(interp, objPtr);
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
    dprintf("Called");

    /* Validate arg count */
    if (objc == 1) {
	return DigestList(interp);

    } else if (objc == 2) {
	return DigestInfo(interp, Tcl_GetStringFromObj(objv[1],NULL));

    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?name?");
	return TCL_ERROR;
    }
    return TCL_OK;
	clientData = clientData;
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
int MacInfo(Tcl_Interp *interp, char *macName) {
     return TCL_OK;
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
    Tcl_Obj *objPtr = Tcl_NewListObj(0, NULL);
    if (objPtr == NULL) {
	return TCL_ERROR;
    }

    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj("cmac", -1));
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj("hmac", -1));
    Tcl_SetObjResult(interp, objPtr);
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
    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc == 1) {
	return MacList(interp);

    } else if (objc == 2) {
	return MacInfo(interp, Tcl_GetStringFromObj(objv[1],NULL));

    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?name?");
	return TCL_ERROR;
    }
    return TCL_OK;
	clientData = clientData;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * PkeyInfo --
 *
 *	Return a list of properties and values for pkeyName.
 *
 * Results:
 *	A standard Tcl list.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int PkeyInfo(Tcl_Interp *interp, char *pkeyName) {
     return TCL_OK;
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
    Tcl_Obj *objPtr = Tcl_NewListObj(0, NULL);
    if (objPtr == NULL) {
	return TCL_ERROR;
    }

    for (size_t i = 0; i < EVP_PKEY_meth_get_count(); i++) {
        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_get0(i);
        int pkey_id, pkey_flags;

        EVP_PKEY_meth_get0_info(&pkey_id, &pkey_flags, pmeth);
	/*LAPPEND_STR(interp, objPtr, "name", OBJ_nid2ln(pkey_id), -1);
	LAPPEND_STR(interp, objPtr, "type", pkey_flags & ASN1_PKEY_DYNAMIC ? "External" : "Built-in", -1);*/

	Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj(OBJ_nid2ln(pkey_id), -1));
    }
    Tcl_SetObjResult(interp, objPtr);
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
    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc == 1) {
	return PkeyList(interp);

    } else if (objc == 2) {
	return PkeyInfo(interp, Tcl_GetStringFromObj(objv[1],NULL));

    } else {
	Tcl_WrongNumArgs(interp, 1, objv, "?name?");
	return TCL_ERROR;
    }
    return TCL_OK;
	clientData = clientData;
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
    Tcl_Obj *objPtr;

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
    objPtr = Tcl_NewListObj(0, NULL);
    if (objPtr == NULL) {
	return TCL_ERROR;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(NO_SSL2) && !defined(OPENSSL_NO_SSL2)
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj(protocols[TLS_SSL2], -1));
#endif
#if !defined(NO_SSL3) && !defined(OPENSSL_NO_SSL3) && !defined(OPENSSL_NO_SSL3_METHOD)
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj(protocols[TLS_SSL3], -1));
#endif
#if !defined(NO_TLS1) && !defined(OPENSSL_NO_TLS1) && !defined(OPENSSL_NO_TLS1_METHOD)
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj(protocols[TLS_TLS1], -1));
#endif
#if !defined(NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1_METHOD)
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj(protocols[TLS_TLS1_1], -1));
#endif
#if !defined(NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2_METHOD)
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj(protocols[TLS_TLS1_2], -1));
#endif
#if !defined(NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3)
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj(protocols[TLS_TLS1_3], -1));
#endif
    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
	clientData = clientData;
}

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
    Tcl_Obj *objPtr;

    dprintf("Called");

    /* Validate arg count */
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }

    objPtr = Tcl_NewStringObj(OPENSSL_VERSION_TEXT, -1);
    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
	clientData = clientData;
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

    Tcl_CreateObjCommand(interp, "tls::cipher", CipherObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::ciphers", CiphersObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::digests", DigestsObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::macs", MacsObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::pkeys", PkeysObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::protocols", ProtocolsObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::version", VersionObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}
