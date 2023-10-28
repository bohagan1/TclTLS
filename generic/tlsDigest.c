/*
 * Digest Commands
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

/* Constants */
const char *hex = "0123456789ABCDEF";
#define REASON()	ERR_reason_error_string(ERR_get_error())


/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestFile --
 *
 *	Return message digest for file using user specified hash function.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Result is message digest or error message
 *
 *-------------------------------------------------------------------
 */
int
DigestFile(Tcl_Interp *interp, Tcl_Obj *filename, const EVP_MD *md, int format) {
    EVP_MD_CTX *ctx;
    Tcl_Channel chan;
    char buf[32768];
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    /* Open file channel */
    chan = Tcl_FSOpenFileChannel(interp, filename, "rb", 0444);
    if (chan == NULL) {
	return TCL_ERROR;
    }

    /* Configure channel */
    if (Tcl_SetChannelOption(interp, chan, "-translation", "binary") == TCL_ERROR ||
	Tcl_SetChannelOption(interp, chan, "-buffersize", "32768") == TCL_ERROR) {
	Tcl_Close(interp, chan);
	return TCL_ERROR;
    }

    /* Create message digest context */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
	Tcl_AppendResult(interp, "Create digest context failed: ", REASON(), NULL);
	Tcl_Close(interp, chan);
	return TCL_ERROR;
    }

    /* Initialize hash function */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!EVP_DigestInit_ex(ctx, md, NULL))
#else
    if (!EVP_DigestInit_ex2(ctx, md, NULL))
#endif
    {
	Tcl_AppendResult(interp, "Initialize digest failed: ", REASON(), NULL);
	Tcl_Close(interp, chan);
	EVP_MD_CTX_free(ctx);
	return TCL_ERROR;
    }

    /* Read file data and update hash function */
    while (!Tcl_Eof(chan)) {
	int len = Tcl_ReadRaw(chan, buf, 32768);
	if (!EVP_DigestUpdate(ctx, &buf, (size_t) len)) {
	    Tcl_AppendResult(interp, "Update digest failed: ", REASON(), NULL);
	    Tcl_Close(interp, chan);
	    EVP_MD_CTX_free(ctx);
	    return TCL_ERROR;
	}
    }

    /* Close channel */
    if (Tcl_Close(interp, chan) == TCL_ERROR) {
	EVP_MD_CTX_free(ctx);
	return TCL_ERROR;
    }

    /* Finalize hash function and calculate message digest */
    if (!EVP_DigestFinal_ex(ctx, md_buf, &md_len)) {
	Tcl_AppendResult(interp, "Finalize digest failed: ", REASON(), NULL);
	EVP_MD_CTX_free(ctx);
	return TCL_ERROR;
    }
    EVP_MD_CTX_free(ctx);

    /* Return message digest as either a binary or hex string */
    if (format == 0) {
	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(md_buf, md_len));

    } else {
	Tcl_Obj *resultObj = Tcl_NewObj();
	unsigned char *ptr = Tcl_SetByteArrayLength(resultObj, md_len*2);

	for (unsigned int i = 0; i < md_len; i++) {
	    *ptr++ = hex[(md_buf[i] >> 4) & 0x0F];
	    *ptr++ = hex[md_buf[i] & 0x0F];
	}
	Tcl_SetObjResult(interp, resultObj);
    }
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestHashFunction --
 *
 *	 Calculate message digest using hash function.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to message digest or error message
 *
 *-------------------------------------------------------------------
 */
int
DigestHashFunction(Tcl_Interp *interp, int objc, Tcl_Obj *const objv[], const EVP_MD *md, int format) {
    char *data;
    int len;
    unsigned int md_len;
    unsigned char md_buf[EVP_MAX_MD_SIZE];

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

    /* Calculate hash value, create bin/hex representation, and write to result */
    if (EVP_Digest(data, (size_t) len, md_buf, &md_len, md, NULL)) {
	if (format == 0) {
	    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(md_buf, md_len));

	} else {
	    Tcl_Obj *resultObj = Tcl_NewObj();
	    unsigned char *ptr = Tcl_SetByteArrayLength(resultObj, md_len*2);

	    for (unsigned int i = 0; i < md_len; i++) {
		*ptr++ = hex[(md_buf[i] >> 4) & 0x0F];
		*ptr++ = hex[md_buf[i] & 0x0F];
	    }
	Tcl_SetObjResult(interp, resultObj);
	}

    } else {
	Tcl_AppendResult(interp, "Hash calculation error:", REASON(), (char *) NULL);
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * DigestObjCmd --
 *
 *	Return message digest using user specified hash function.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to message digest or error message
 *
 *-------------------------------------------------------------------
 */
static int
DigestObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int idx, len, format = 1, key_len = 0, data_len = 0;
    const char *digestname;
    Tcl_Obj *dataObj = NULL, *fileObj = NULL;
    unsigned char *key = NULL;
    const EVP_MD *md;

    Tcl_ResetResult(interp);

    if (objc < 3 || objc > 5) {
	Tcl_WrongNumArgs(interp, 1, objv, "type ?-bin|-hex? [-channel chan | -file filename | ?-data? data]");
	return TCL_ERROR;
    }

    /* Get digest */
    digestname = Tcl_GetStringFromObj(objv[1], &len);
    if (digestname == NULL || (md = EVP_get_digestbyname(digestname)) == NULL) {
	Tcl_AppendResult(interp, "Invalid digest type \"", digestname, "\"", NULL);
	return TCL_ERROR;
    }

    /* Optimal case for blob of data */
    if (objc == 3) {
	return DigestHashFunction(interp, --objc, ++objv, md, format);
    }

    /* Get options */
    for (idx = 2; idx < objc-1; idx++) {
	char *opt = Tcl_GetStringFromObj(objv[idx], NULL);

	if (opt[0] != '-')
	    break;

	OPTFLAG("-bin", format, 0);
	OPTFLAG("-binary", format, 0);
	OPTFLAG("-hex", format, 1);
	OPTFLAG("-hexadecimal", format, 1);
	OPTOBJ("-data", dataObj);
	OPTOBJ("-file", fileObj);
	OPTOBJ("-filename", fileObj);

	OPTBAD("option", "-bin, -data, -file, -filename, -key, or -hex");
	return TCL_ERROR;
    }

    /* If no option for last arg, then its the data */
    if (idx < objc) {
	dataObj = objv[idx];
    }

    /* Calc digest on file or data blob */
    if (fileObj != NULL) {
	return DigestFile(interp, fileObj, md, format);
    } else if (dataObj != NULL) {
	Tcl_Obj *objs[2];
	objs[0] = NULL;
	objs[1] = dataObj;
	return DigestHashFunction(interp, 2, objs, md, format);
    }

    Tcl_AppendResult(interp, "No data specified.", NULL);
    return TCL_ERROR;
}

/*
 *-------------------------------------------------------------------
 *
 * Message Digest Convenience Commands --
 *
 *	Convenience commands for message digests.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to message digest or error message
 *
 *-------------------------------------------------------------------
 */
int DigestMD4Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return DigestHashFunction(interp, objc, objv, EVP_md4(), 1);
}

int DigestMD5Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return DigestHashFunction(interp, objc, objv, EVP_md5(), 1);
}

int DigestSHA1Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return DigestHashFunction(interp, objc, objv, EVP_sha1(), 1);
}

int DigestSHA256Cmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return DigestHashFunction(interp, objc, objv, EVP_sha256(), 1);
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

