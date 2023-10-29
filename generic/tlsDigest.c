/*
 * Digest Command and Stacked Transform Channel
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


/*
 * This structure describes the per-instance state of an SSL channel.
 *
 * The SSL processing context is maintained here, in the ClientData
 */
typedef struct DigestState {
	Tcl_Channel self;	/* This socket channel */
	Tcl_TimerToken timer;	/* Timer for read events */

	int flags;		/* Chan config flags */
	int watchMask;		/* Current WatchProc mask */
	int mode;		/* Current mode of parent channel */
	int format;		/* Output format */

	Tcl_Interp *interp;	/* Current interpreter */
	EVP_MD_CTX *ctx;	/* MD Context */
} DigestState;

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
int DigestFile(Tcl_Interp *interp, Tcl_Obj *filename, const EVP_MD *md, int format) {
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
	if (len > 0 && !EVP_DigestUpdate(ctx, &buf, (size_t) len)) {
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
 * DigestBlockModeProc --
 *
 *	This procedure is invoked by the generic IO level
 *       to set blocking and nonblocking modes.
 *
 * Returns:
 *	0 if successful or POSIX error code if failed.
 *
 * Side effects:
 *	Sets the device into blocking or nonblocking mode.
 *	Can call Tcl_SetChannelError.
 *
 *-------------------------------------------------------------------
 */
static int DigestBlockModeProc(ClientData clientData, int mode) {
    DigestState *statePtr = (DigestState *) clientData;

    if (mode == TCL_MODE_NONBLOCKING) {
	statePtr->flags |= TLS_TCL_ASYNC;
    } else {
	statePtr->flags &= ~(TLS_TCL_ASYNC);
    }
    return 0;
}

/*
 *-------------------------------------------------------------------
 *
 * DigestFree --
 *
 *	This procedure removes a digest state structure
 *
 * Returns:
 *	Nothing
 *
 * Side effects:
 *	Removes structure
 *
 *-------------------------------------------------------------------
 */
void DigestFree (DigestState *statePtr) {
    if (statePtr == (DigestState *) NULL) return;
    
    if (statePtr->ctx != NULL) {
	EVP_MD_CTX_free(statePtr->ctx);
    }
    ckfree(statePtr);
}

/*
 *-------------------------------------------------------------------
 *
 * DigestCloseProc --
 *
 *	This procedure is invoked by the generic IO level to perform
 *	channel-type-specific cleanup when digest channel is closed.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Writes digest to output and closes the channel.
 *
 *-------------------------------------------------------------------
 */
int DigestCloseProc(ClientData clientData, Tcl_Interp *interp) {
    DigestState *statePtr = (DigestState *) clientData;
    int result = 0;

    /* Cancel active timer, if any */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
    }

    /* Clean-up */
    DigestFree(statePtr);
    return result;
}

/*
 * Same as DigestCloseProc but with individual read and write close control
 */
static int DigestClose2Proc(ClientData instanceData, Tcl_Interp *interp, int flags) {

    if ((flags & (TCL_CLOSE_READ | TCL_CLOSE_WRITE)) == 0) {
	return DigestCloseProc(instanceData, interp);
    }
    return EINVAL;
}

/*
 *----------------------------------------------------------------------
 *
 * DigestInputProc --
 *
 *	Called by the generic IO system to read data from transform.
 *
 * Returns:
 *	Total bytes read
 *
 * Side effects:
 *	Read data from transform and write to buf
 *
 *----------------------------------------------------------------------
 */
int DigestInputProc(ClientData clientData, char *buf, int toRead, int *errorCodePtr) {
    DigestState *statePtr = (DigestState *) clientData;
    Tcl_Channel parent;
    int read;
    *errorCodePtr = 0;

    if (toRead <= 0 || statePtr->self == (Tcl_Channel) NULL) {
	return 0;
    }

    /* Get bytes from underlying channel */
    parent = Tcl_GetStackedChannel(statePtr->self);
    read = Tcl_ReadRaw(parent, buf, toRead);

    /* Add to message digest */
    if (read > 0) {
	/* OK */
	if (!EVP_DigestUpdate(statePtr->ctx, buf, read)) {
	    Tcl_SetChannelError(statePtr->self, Tcl_ObjPrintf("Digest update failed: %s", REASON()));
	    *errorCodePtr = EINVAL;
	    return -1;
	}
	*errorCodePtr = EAGAIN;
	read = -1;
	    
    } else if (read < 0) {
	/* Error */
	*errorCodePtr = Tcl_GetErrno();

    } else if (!(statePtr->flags & 0x10)) {
	/* EOF */
	*errorCodePtr = 0;
	unsigned char md_buf[EVP_MAX_MD_SIZE];
	unsigned int md_len = 0;

	/* Get message digest */
	if (!EVP_DigestFinal_ex(statePtr->ctx, md_buf, &md_len)) {
	    *errorCodePtr = EINVAL;

	/* Write message digest to output channel as byte array or hex string */
	} else if (md_len > 0) {
	    if (statePtr->format == 0) {
		read = md_len;
		memcpy(buf, md_buf, read);

	    } else {
		unsigned char hex_buf[EVP_MAX_MD_SIZE*2];
		unsigned char *ptr = hex_buf;

		for (unsigned int i = 0; i < md_len; i++) {
		    *ptr++ = hex[(md_buf[i] >> 4) & 0x0F];
		    *ptr++ = hex[md_buf[i] & 0x0F];
		}
		read = md_len*2;
		memcpy(buf, hex_buf, read);
	    }
	}
	statePtr->flags |= 0x10;
    }
    return read;
}

/*
 *----------------------------------------------------------------------
 *
 * DigestOutputProc --
 *
 *	Called by the generic IO system to write data to transform.
 *
 * Returns:
 *	Total bytes written
 *
 * Side effects:
 *	Get data from buf and update digest
 *
 *----------------------------------------------------------------------
 */
 int DigestOutputProc(ClientData clientData, const char *buf, int toWrite, int *errorCodePtr) {
    DigestState *statePtr = (DigestState *) clientData;
    *errorCodePtr = 0;

    if (toWrite <= 0 || statePtr->self == (Tcl_Channel) NULL) {
	return 0;
    }
    return toWrite;
}

/*
 *----------------------------------------------------------------------
 *
 * DigestSetOptionProc --
 *
 *	Called by the generic IO system to set channel option to value.
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR if failed.
 *
 * Side effects:
 *	Updates channel option to new value.
 *
 *----------------------------------------------------------------------
 */
static int DigestSetOptionProc(ClientData clientData, Tcl_Interp *interp, const char *optionName,
	const char *optionValue) {
    DigestState *statePtr = (DigestState *) clientData;
    Tcl_Channel parent;
    Tcl_DriverSetOptionProc *setOptionProc;

    if (statePtr->self == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Delegate options downstream */
    parent = Tcl_GetStackedChannel(statePtr->self);
    setOptionProc = Tcl_ChannelSetOptionProc(Tcl_GetChannelType(parent));
    if (setOptionProc != NULL) {
	return (*setOptionProc)(Tcl_GetChannelInstanceData(parent), interp, optionName, optionValue);
    } else {
	return TCL_ERROR;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * DigestGetOptionProc --
 *
 *	Called by the generic IO system to get channel option's value.
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR if failed.
 *
 * Side effects:
 *	Sets result to option's value
 *
 *----------------------------------------------------------------------
 */
static int DigestGetOptionProc(ClientData clientData, Tcl_Interp *interp, const char *optionName,
	Tcl_DString *optionValue) {
    DigestState *statePtr = (DigestState *) clientData;
    Tcl_Channel parent;
    Tcl_DriverGetOptionProc *getOptionProc;

    if (statePtr->self == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Delegate options downstream */
    parent = Tcl_GetStackedChannel(statePtr->self);
    getOptionProc = Tcl_ChannelGetOptionProc(Tcl_GetChannelType(parent));
    if (getOptionProc != NULL) {
	return (*getOptionProc)(Tcl_GetChannelInstanceData(parent), interp, optionName, optionValue);
    } else if (optionName == (char*) NULL) {
	/* Request is query for all options, this is ok. */
	return TCL_OK;
    }

    /* Request for a specific option has to fail, we don't have any. */
    return Tcl_BadChannelOption(interp, optionName, "");
}

/*
 *----------------------------------------------------------------------
 *
 * DigestTimerHandler --
 *
 *	Called by the notifier via timer to flush out pending input data.
 *
 * Returns:
 *	Nothing
 *
 * Side effects:
 *	May call Tcl_NotifyChannel
 *
 *----------------------------------------------------------------------
 */
static void DigestTimerHandler(ClientData clientData) {
    DigestState *statePtr = (DigestState *) clientData;

    if (statePtr->self == (Tcl_Channel) NULL) {
	return;
    }

    /* Clear timer token */
    statePtr->timer = (Tcl_TimerToken) NULL;

    /* Fire event if there is pending data, skip otherwise */
    if ((statePtr->watchMask & TCL_READABLE) && (Tcl_InputBuffered(statePtr->self) > 0)) {
	Tcl_NotifyChannel(statePtr->self, TCL_READABLE);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * DigestWatchProc --
 *
 *	Initialize the notifier to watch for events from this channel.
 *
 * Returns:
 *	Nothing
 *
 * Side effects:
 *	Configure notifier so future events on the channel will be seen by Tcl.
 *
 *----------------------------------------------------------------------
 */
#define READ_DELAY	5
void DigestWatchProc(ClientData clientData, int mask) {
    DigestState *statePtr = (DigestState *) clientData;
    Tcl_Channel parent;
    Tcl_DriverWatchProc *watchProc;

    if (statePtr->self == (Tcl_Channel) NULL) {
	return;
    }

    /* Store OR-ed combination of TCL_READABLE, TCL_WRITABLE and TCL_EXCEPTION */
    statePtr->watchMask = mask;

    /* Propagate mask info to parent channel */
    parent = Tcl_GetStackedChannel(statePtr->self);
    watchProc = Tcl_ChannelWatchProc(Tcl_GetChannelType(parent));
    watchProc(Tcl_GetChannelInstanceData(parent), mask);

    /* Remove pending timer */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
    }

    /* If there is data pending, set new timer to call Tcl_NotifyChannel */
    if ((mask & TCL_READABLE) && (Tcl_InputBuffered(statePtr->self) > 0)) {
	statePtr->timer = Tcl_CreateTimerHandler(READ_DELAY, DigestTimerHandler, (ClientData) statePtr);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * DigestGetHandleProc --
 *
 *	Called from Tcl_GetChannelHandle to retrieve OS specific file handle
 *	from inside this channel. Not used for transformations?
 *
 * Returns:
 *	If direction is TCL_READABLE return the handle used for input, or if
 *	TCL_WRITABLE return the handle used for output.
 *
 * Side effects:
 *	None
 *
 *----------------------------------------------------------------------
 */
int DigestGetHandleProc(ClientData clientData, int direction, ClientData *handlePtr) {
    DigestState *statePtr = (DigestState *) clientData;

    if (statePtr->self == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }
    return Tcl_GetChannelHandle(Tcl_GetStackedChannel(statePtr->self), direction, handlePtr);
}

/*
 *----------------------------------------------------------------------
 *
 * DigestNotifyProc --
 *
 *	Called by Tcl to inform us of activity on the underlying channel.
 *
 * Returns:
 *	Unchanged interestMask which is an OR-ed combination of TCL_READABLE or TCL_WRITABLE
 *
 * Side effects:
 *	Cancels any pending timer.
 *
 *----------------------------------------------------------------------
 */
int DigestNotifyProc(ClientData clientData, int interestMask) {
    DigestState *statePtr = (DigestState *) clientData;

    /* Skip timer event as redundant */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
    }
    return interestMask;
}

/*
 *
 * Channel type structure definition for digest transformations.
 *
 */
static const Tcl_ChannelType digestChannelType = {
    "digest",			/* Type name */
    TCL_CHANNEL_VERSION_5,	/* v5 channel */
    DigestCloseProc,		/* Close proc */
    DigestInputProc,		/* Input proc */
    DigestOutputProc,		/* Output proc */
    NULL,			/* Seek proc */
    DigestSetOptionProc,	/* Set option proc */
    DigestGetOptionProc,	/* Get option proc */
    DigestWatchProc,		/* Initialize notifier */
    DigestGetHandleProc,	/* Get OS handles out of channel */
    DigestClose2Proc,		/* close2proc */
    DigestBlockModeProc,	/* Set blocking/nonblocking mode*/
    NULL,			/* Flush proc */
    DigestNotifyProc,		/* Handling of events bubbling up */
    NULL,			/* Wide seek proc */
    NULL,			/* Thread action */
    NULL			/* Truncate */
};

/*
 *----------------------------------------------------------------------
 *
 * DigestChannel --
 *
 *	Create a stacked channel for a message digest transformation.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Adds transform to channel and sets result to channel name or error message.
 *
 *----------------------------------------------------------------------
 */
static int
DigestChannel(Tcl_Interp *interp, const char *channel, const EVP_MD *md, int format) {
    int mode; /* OR-ed combination of TCL_READABLE and TCL_WRITABLE */
    Tcl_Channel chan;
    EVP_MD_CTX *ctx;
    DigestState *statePtr;

    /* Validate args */
    if (channel == (const char *) NULL || md == (const EVP_MD *) NULL) {
	return TCL_ERROR;
    }

    chan = Tcl_GetChannel(interp, channel, &mode);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);

    /* Create internal storage structures */
    ctx = EVP_MD_CTX_new();
    statePtr = (DigestState *) ckalloc((unsigned) sizeof(DigestState));
    if (ctx != NULL && statePtr != NULL) {
	memset(statePtr, 0, sizeof(DigestState));
	statePtr->self	= chan;		/* This socket channel */
	statePtr->timer = (Tcl_TimerToken) NULL;	/* Timer to flush data */
	statePtr->flags = 0;		/* Chan config flags */
	statePtr->watchMask = 0;	/* Current WatchProc mask */
	statePtr->mode	= mode;		/* Current mode of parent channel */
	statePtr->format = format;	/* Output format */
	statePtr->interp = interp;	/* Current interpreter */
	statePtr->ctx = ctx;		/* SSL Context */
    } else {
	Tcl_AppendResult(interp, "Initialize digest error: memory allocation failure", (char *) NULL);
	EVP_MD_CTX_free(ctx);
	DigestFree(statePtr);
	return TCL_ERROR;
    }

    /* Initialize digest */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if (!EVP_DigestInit_ex(ctx, md, NULL))
#else
    if (!EVP_DigestInit_ex2(ctx, md, NULL))
#endif
    {
	Tcl_AppendResult(interp, "Initialize digest error: ", REASON(), (char *) NULL);
	EVP_MD_CTX_free(ctx);
	DigestFree(statePtr);
	return TCL_ERROR;
    }

    /* Configure channel */
    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
    if (Tcl_GetChannelBufferSize(chan) < EVP_MAX_MD_SIZE * 2) {
	Tcl_SetChannelBufferSize(chan, EVP_MAX_MD_SIZE * 2);
    }

    /* Stack channel */
    statePtr->self = Tcl_StackChannel(interp, &digestChannelType, (ClientData) statePtr, mode, chan);
    if (statePtr->self == (Tcl_Channel) NULL) {
	EVP_MD_CTX_free(ctx);
	DigestFree(statePtr);
	return TCL_ERROR;
    }

    Tcl_SetResult(interp, (char *) Tcl_GetChannelName(chan), TCL_VOLATILE);
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
    const char *digestname, *channel = NULL;
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
	OPTSTR("-chan", channel);
	OPTSTR("-channel", channel);
	OPTOBJ("-file", fileObj);
	OPTOBJ("-filename", fileObj);

	OPTBAD("option", "-bin, -data, -file, -filename, -key, or -hex");
	return TCL_ERROR;
    }

    /* If no option for last arg, then its the data */
    if (idx < objc) {
	dataObj = objv[idx];
    }

    /* Calc digest on file, stacked channel, or data blob */
    if (fileObj != NULL) {
	return DigestFile(interp, fileObj, md, format);
    } else if (channel != NULL) {
	return DigestChannel(interp, channel, md, format);
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

