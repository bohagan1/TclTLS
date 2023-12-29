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
#include <openssl/rand.h>

/*******************************************************************/

/* Options for Random commands */

static const char *command_opts [] = {
    "-private", NULL};

enum _command_opts {
    _opt_private
};

/*
 *-------------------------------------------------------------------
 *
 * RAND_Random --
 *
 *	Generate random byes using a random bytes using a cryptographically
 *	secure pseudo random generator (CSPRNG).
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to the random bytes, or an error message
 *
 *-------------------------------------------------------------------
 */
static int RAND_Random(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int out_len = 0, res;
    unsigned char *out_buf;
    Tcl_Obj *resultObj;
    (void) clientData;

    dprintf("Called");

    /* Clear errors */
    Tcl_ResetResult(interp);
    ERR_clear_error();

    /* Validate arg count */
    if (objc < 2 || objc > 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-private? length");
	return TCL_ERROR;
    } else if (objc == 3) {
	int fn;
	if (Tcl_GetIndexFromObj(interp, objv[1], command_opts, "option", 0, &fn) != TCL_OK) {
	    return TCL_ERROR;
	}
    }

    /* Get length */
    if (Tcl_GetIntFromObj(interp, objv[objc - 1], &out_len) != TCL_OK) {
	return TCL_ERROR;
    }
    if (out_len < 0) {
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("bad count \"%d\": must be integer >= 0", out_len));
	return TCL_ERROR;
    }

    /* Allocate storage for result */
    resultObj = Tcl_NewObj();
    out_buf = Tcl_SetByteArrayLength(resultObj, out_len);
    if (resultObj == NULL || out_buf == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	Tcl_DecrRefCount(resultObj);
	return TCL_ERROR;
    }

    /* Get random bytes */
    if (objc == 2) {
	res = RAND_bytes(out_buf, out_len);
    } else {
	res = RAND_priv_bytes(out_buf, out_len);
    }
    if (!res) {
	Tcl_AppendResult(interp, "Generate failed: ", REASON(), (char *) NULL);
	Tcl_DecrRefCount(resultObj);
	return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, resultObj);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_RandCommands --
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
int Tls_RandCommands(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "tls::random", RAND_Random, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}

