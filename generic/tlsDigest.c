/*
 * Digest Commands
 *
 * Copyright (C) 2023 Brian O'Hagan
 *
 */

#include "tlsInt.h"
#include <tcl.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

/* Constants */
const char *hex = "0123456789ABCDEF";


/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * Hash Calc --
 *
 *	Calculate message digest of data using type hash algorithm.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
int
HashCalc(Tcl_Interp *interp, int objc, Tcl_Obj *const objv[], const EVP_MD *type) {
    char *data;
    int len;
    unsigned int mdlen;
    unsigned char mdbuf[EVP_MAX_MD_SIZE];

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "data");
	return TCL_ERROR;
    }

    /* Get data */
    data = Tcl_GetByteArrayFromObj(objv[1], &len);
    if (data == NULL || len == 0) {
	Tcl_SetResult(interp, "No data", NULL);
	return TCL_ERROR;
    }

    /* Calculate hash value, create hex representation, and write to result */
    if (EVP_Digest(data, (size_t) len, mdbuf, &mdlen, type, NULL)) {
	Tcl_Obj *resultObj;
	unsigned char *ptr;
	resultObj = Tcl_NewObj();
	ptr = Tcl_SetByteArrayLength(resultObj, mdlen*2);

	for (unsigned int i = 0; i < mdlen; i++) {
	    *ptr++ = hex[(mdbuf[i] >> 4) & 0x0F];
	    *ptr++ = hex[mdbuf[i] & 0x0F];
	}
	Tcl_SetObjResult(interp, resultObj);
    } else {
	Tcl_SetResult(interp, "Hash calculation error", NULL);
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * Hash Commands --
 *
 *	Return the digest as a hex string for data using type message digest.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	None.
 *
 *-------------------------------------------------------------------
 */
DigestObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int len;
    const char *name;
    const EVP_MD *type;

    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "type data");
	return TCL_ERROR;
    }

    name = Tcl_GetStringFromObj(objv[1],&len);
    if (name == NULL || (type = EVP_get_digestbyname(name)) == NULL) {
	Tcl_AppendResult(interp, "Invalid digest type \"", name, "\"", NULL);
	return TCL_ERROR;
    }
    objc--;
    objv++;
    return HashCalc(interp, objc, objv, type);
}

/*
 * Command to Calculate MD4 Message Digest
 */
int
DigestMD4Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return HashCalc(interp, objc, objv, EVP_md4());
}

/*
 * Command to Calculate MD5 Message Digest
 */
int
DigestMD5Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return HashCalc(interp, objc, objv, EVP_md5());
}

/*
 * Command to Calculate SHA-1 Hash
 */
int
DigestSHA1Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return HashCalc(interp, objc, objv, EVP_sha1());
}

/*
 * Command to Calculate SHA2 SHA-256 Hash
 */
int
DigestSHA256Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return HashCalc(interp, objc, objv, EVP_sha256());
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_DigestCommands --
 *
 *	Create digest commands
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Creates commands
 *
 *-------------------------------------------------------------------
 */
int Tls_DigestCommands(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tls::digest", DigestObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::md4", DigestMD4Cmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::md5", DigestMD5Cmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::sha1", DigestSHA1Cmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::sha256", DigestSHA256Cmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}

