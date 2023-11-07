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

    /* Fields: (int) type and alias, (const char*) name and data */
    if (1 || !obj->alias) {
	/* Filter out signed digests (a.k.a signature algorithms) */
	if (strstr(obj->name, "rsa") == NULL && strstr(obj->name, "RSA") == NULL) {
	    Tcl_ListObjAppendElement(NULL, objPtr, Tcl_NewStringObj(obj->name,-1));
	}
    }
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
    int index, verbose = 0, use_supported = 0;

    dprintf("Called");

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_ciphers(); /* Make sure they're loaded */
#endif

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
	Tcl_Obj *objPtr = Tcl_NewListObj(0, NULL);

	OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, NamesCallback, (void *) objPtr);
	Tcl_SetObjResult(interp, objPtr);
	return TCL_OK;

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

	    for (int i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
		/* uint32_t id;*/
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c == NULL) continue;

		/* Get OpenSSL-specific ID, not IANA ID */
		/*id = SSL_CIPHER_get_id(c);*/

		/* TLS protocol two-byte id */
		/*id = SSL_CIPHER_get_protocol_id(c);*/

		/* Standard RFC name of cipher or (NONE) */
		/*const char *nm = SSL_CIPHER_standard_name(c);
		if (nm == NULL) {nm = "UNKNOWN";}*/

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

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return TCL_OK;
	clientData = clientData;
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
    Tcl_Obj *objPtr;

    dprintf("Called");

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_digests(); /* Make sure they're loaded */
#endif

    /* Validate arg count */
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }

    /* List all digests */
    objPtr = Tcl_NewListObj(0, NULL);
    OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, NamesCallback, (void *) objPtr);
    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
	clientData = clientData;
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
    Tcl_Obj *objPtr;

    dprintf("Called");

    /* Validate arg count */
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }

    /* List all MACs */
    objPtr = Tcl_NewListObj(0, NULL);
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj("cmac", -1));
    Tcl_ListObjAppendElement(interp, objPtr, Tcl_NewStringObj("hmac", -1));
    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
	clientData = clientData;
}

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

    /* Validate arg count */
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }

    /* List all MACs */
    objPtr = Tcl_NewListObj(0, NULL);
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
    Tcl_CreateObjCommand(interp, "tls::ciphers", CiphersObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::digests", DigestsObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::macs", MacsObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::protocols", ProtocolsObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::version", VersionObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}
