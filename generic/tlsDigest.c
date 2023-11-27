/*
 * Message Digest (MD) and Message Authentication Code (MAC) Module
 *
 * Provides commands to calculate a message digest (MD) or message
 * authentication code (MAC) using a specified hash function and/or cipher.
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
#include <openssl/cmac.h>
#include <openssl/hmac.h>

/* Constants */
const char *hex = "0123456789abcdef";

/* Macros */
#define BUFFER_SIZE	65536
#define CHAN_EOF	0x10
#define READ_DELAY	5

/* Digest format and operation */
#define BIN_FORMAT	0x01
#define HEX_FORMAT	0x02
#define IS_XOF		0x08
#define TYPE_MD		0x10
#define TYPE_HMAC	0x20
#define TYPE_CMAC	0x40
#define TYPE_MAC	0x80

#if OPENSSL_VERSION_NUMBER <= 0x30000000L
#define EVP_MAC void
#endif

/*
 * This structure defines the per-instance state of a digest operation.
 */
typedef struct DigestState {
	Tcl_Channel self;	/* This socket channel */
	Tcl_TimerToken timer;	/* Timer for read events */

	int flags;		/* Chan config flags */
	int watchMask;		/* Current WatchProc mask */
	int mode;		/* Current mode of parent channel */
	int format;		/* Digest format and operation */

	Tcl_Interp *interp;	/* Current interpreter */
	EVP_MD_CTX *ctx;	/* MD Context */
	HMAC_CTX *hctx;		/* HMAC context */
	CMAC_CTX *cctx;		/* CMAC context */
	Tcl_Command token;	/* Command token */
} DigestState;

/*
 *-------------------------------------------------------------------
 *
 * DigestStateNew --
 *
 *	This function creates a per-instance state data structure
 *
 * Returns:
 *	Digest structure pointer
 *
 * Side effects:
 *	Creates structure
 *
 *-------------------------------------------------------------------
 */
DigestState *DigestStateNew(Tcl_Interp *interp, int format) {
    DigestState *statePtr;

    statePtr = (DigestState *) ckalloc((unsigned) sizeof(DigestState));
    if (statePtr != NULL) {
	memset(statePtr, 0, sizeof(DigestState));
	statePtr->self	= NULL;		/* This socket channel */
	statePtr->timer = NULL;		/* Timer to flush data */
	statePtr->flags = 0;		/* Chan config flags */
	statePtr->watchMask = 0;	/* Current WatchProc mask */
	statePtr->mode	= 0;		/* Current mode of parent channel */
	statePtr->format = format;	/* Digest format and operation */
	statePtr->interp = interp;	/* Current interpreter */
	statePtr->ctx = NULL;		/* MD Context */
	statePtr->hctx = NULL;		/* HMAC Context */
	statePtr->cctx = NULL;		/* CMAC Context */
	statePtr->token = NULL;		/* Command token */
    }
    return statePtr;
}

/*
 *-------------------------------------------------------------------
 *
 * DigestStateFree --
 *
 *	This function deletes a digest state structure
 *
 * Returns:
 *	Nothing
 *
 * Side effects:
 *	Removes structure
 *
 *-------------------------------------------------------------------
 */
void DigestStateFree(DigestState *statePtr) {
    if (statePtr == (DigestState *) NULL) {
	return;
    }

    /* Remove pending timer */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
    }

    /* Free context structures */
    if (statePtr->ctx != (EVP_MD_CTX *) NULL) {
	EVP_MD_CTX_free(statePtr->ctx);
    }
    if (statePtr->hctx != (HMAC_CTX *) NULL) {
	HMAC_CTX_free(statePtr->hctx);
    }
    if (statePtr->cctx != (CMAC_CTX *) NULL) {
	CMAC_CTX_free(statePtr->cctx);
    }
    ckfree(statePtr);
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestInitialize --
 *
 *	Initialize a hash function
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR for failure with result set
 *	to error message.
 *
 * Side effects:
 *	No result or error message
 *
 *-------------------------------------------------------------------
 */
int DigestInitialize(Tcl_Interp *interp, DigestState *statePtr, const EVP_MD *md,
	const EVP_CIPHER *cipher, Tcl_Obj *keyObj, EVP_MAC *mac) {
    int key_len = 0, res = 0;
    const unsigned char *key = NULL;

    /* Create contexts */
    switch(statePtr->format & 0xFF0) {
    case TYPE_MD:
	statePtr->ctx = EVP_MD_CTX_new();
	res = (statePtr->ctx != NULL);
	break;
    case TYPE_HMAC:
	statePtr->hctx = HMAC_CTX_new();
	res = (statePtr->hctx != NULL);
	break;
    case TYPE_CMAC:
	statePtr->cctx = CMAC_CTX_new();
	res = (statePtr->cctx != NULL);
	break;
    }

    if (!res) {
	Tcl_AppendResult(interp, "Create context failed: ", REASON(), NULL);
	return TCL_ERROR;
    }

    /* Get key */
    if (keyObj != NULL) {
	key = Tcl_GetByteArrayFromObj(keyObj, &key_len);
    }

    /* Initialize cryptography function */
    switch(statePtr->format & 0xFF0) {
    case TYPE_MD:
	res = EVP_DigestInit_ex(statePtr->ctx, md, NULL);
	break;
    case TYPE_HMAC:
	res = HMAC_Init_ex(statePtr->hctx, (const void *) key, key_len, md, NULL);
	break;
    case TYPE_CMAC:
	res = CMAC_Init(statePtr->cctx, (const void *) key, key_len, cipher, NULL);
	break;
    }

    if (!res) {
	Tcl_AppendResult(interp, "Initialize failed: ", REASON(), NULL);
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * DigestUpdate --
 *
 *	Update a hash function with data
 *
 * Returns:
 *	1 if successful or 0 for failure
 *
 * Side effects:
 *	Adds buf data to hash function or sets result to error message
 *
 *-------------------------------------------------------------------
 */
int DigestUpdate(DigestState *statePtr, char *buf, size_t read, int do_result) {
    int res = 0;

    switch(statePtr->format & 0xFF0) {
    case TYPE_MD:
        res = EVP_DigestUpdate(statePtr->ctx, buf, read);
	break;
    case TYPE_HMAC:
        res = HMAC_Update(statePtr->hctx, buf, read);
	break;
    case TYPE_CMAC:
        res = CMAC_Update(statePtr->cctx, buf, read);
	break;
    }

    if (!res && do_result) {
	Tcl_AppendResult(statePtr->interp, "Update failed: ", REASON(), NULL);
	return TCL_ERROR;
    }
    return res;
}

/*
 *-------------------------------------------------------------------
 *
 * DigestFinalize --
 *
 *	Finalize a hash function and return the message digest
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR for failure with result set
 *	to error message.
 *
 * Side effects:
 *	Sets result to message digest or an error message.
 *
 *-------------------------------------------------------------------
 */
int DigestFinalize(Tcl_Interp *interp, DigestState *statePtr, Tcl_Obj **resultObj) {
    unsigned char md_buf[EVP_MAX_MD_SIZE];
    unsigned int ulen;
    int res = 0, md_len = 0;

    /* Finalize cryptography function and get result */
    switch(statePtr->format & 0xFF0) {
    case TYPE_MD:
	if (!(statePtr->format & IS_XOF)) {
	    res = EVP_DigestFinal_ex(statePtr->ctx, md_buf, &ulen);
	    md_len = (int) ulen;
	} else {
	    res = EVP_DigestFinalXOF(statePtr->ctx, md_buf, (size_t) EVP_MAX_MD_SIZE);
	    md_len = EVP_MAX_MD_SIZE;
	}
	break;
    case TYPE_HMAC:
	res = HMAC_Final(statePtr->hctx, md_buf, &ulen);
	md_len = (int) ulen;
	break;
    case TYPE_CMAC:
	size_t size;
	res = CMAC_Final(statePtr->cctx, md_buf, &size);
	md_len = (int) size;
	break;
    }

    if (!res) {
	if (resultObj == NULL) {
	    Tcl_AppendResult(interp, "Finalize failed: ", REASON(), NULL);
	}
	return TCL_ERROR;
    }

    /* Return message digest as either a binary or hex string */
    if (statePtr->format & BIN_FORMAT) {
	if (resultObj == NULL) {
	    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(md_buf, md_len));
	} else {
	    *resultObj = Tcl_NewByteArrayObj(md_buf, md_len);
	    Tcl_IncrRefCount(*resultObj);
	}

    } else {
	Tcl_Obj *newObj = Tcl_NewObj();
	unsigned char *ptr = Tcl_SetByteArrayLength(newObj, md_len*2);

	for (int i = 0; i < md_len; i++) {
	    *ptr++ = hex[(md_buf[i] >> 4) & 0x0F];
	    *ptr++ = hex[md_buf[i] & 0x0F];
	}

	if (resultObj == NULL) {
	    Tcl_SetObjResult(interp, newObj);
	} else {
	    *resultObj = newObj;
	    Tcl_IncrRefCount(*resultObj);
	}
    }
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestBlockModeProc --
 *
 *	This function is invoked by the generic IO level
 *	to set blocking and nonblocking modes.
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
 * DigestCloseProc --
 *
 *	This function is invoked by the generic IO level to perform
 *	channel-type specific cleanup when the channel is closed. All
 *	queued output is flushed prior to calling this function.
 *
 * Returns:
 *	0 if successful or POSIX error code if failed.
 *
 * Side effects:
 *	Deletes stored state data.
 *
 *-------------------------------------------------------------------
 */
int DigestCloseProc(ClientData clientData, Tcl_Interp *interp) {
    DigestState *statePtr = (DigestState *) clientData;

    /* Cancel active timer, if any */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
    }

    /* Output message digest if not already done */
    if (!(statePtr->flags & CHAN_EOF)) {
	Tcl_Channel parent = Tcl_GetStackedChannel(statePtr->self);
	Tcl_Obj *resultObj;
	int written;

	if (DigestFinalize(statePtr->interp, statePtr, &resultObj) == TCL_OK) {
	    unsigned char *data = Tcl_GetByteArrayFromObj(resultObj, &written);
	    Tcl_WriteRaw(parent, data, written);
	    Tcl_DecrRefCount(resultObj);
	}
	statePtr->flags |= CHAN_EOF;
    }

    /* Clean-up */
    DigestStateFree(statePtr);
    return 0;
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
 *	Called by the generic IO system to read data from transform and
 *	place in buf. Transform gets data from the underlying channel.
 *
 * Returns:
 *	Total bytes read or -1 for an error along with a POSIX error
 *	code in errorCodePtr. Use EAGAIN for nonblocking and no data.
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

    /* Abort if nothing to process */
    if (toRead <= 0 || statePtr->self == (Tcl_Channel) NULL) {
	return 0;
    }

    /* Get bytes from underlying channel */
    parent = Tcl_GetStackedChannel(statePtr->self);
    read = Tcl_ReadRaw(parent, buf, toRead);

    /* Update hash function */
    if (read > 0) {
	/* Have data */
	if (!DigestUpdate(statePtr, buf, (size_t) read, 0)) {
	    Tcl_SetChannelError(statePtr->self, Tcl_ObjPrintf("Update failed: %s", REASON()));
	    *errorCodePtr = EINVAL;
	    return 0;
	}
	/* This is correct */
	read = -1;
	*errorCodePtr = EAGAIN;

    } else if (read < 0) {
	/* Error */
	*errorCodePtr = Tcl_GetErrno();

    } else if (!(statePtr->flags & CHAN_EOF)) {
	/* EOF */
	Tcl_Obj *resultObj;
	if (DigestFinalize(statePtr->interp, statePtr, &resultObj) == TCL_OK) {
	    unsigned char *data = Tcl_GetByteArrayFromObj(resultObj, &read);
	    memcpy(buf, data, read);
	    Tcl_DecrRefCount(resultObj);

	} else {
	    Tcl_SetChannelError(statePtr->self, Tcl_ObjPrintf("Finalize failed: %s", REASON()));
	    *errorCodePtr = EINVAL;
	    read = 0;
	}
	statePtr->flags |= CHAN_EOF;
    }
    return read;
}

/*
 *----------------------------------------------------------------------
 *
 * DigestOutputProc --
 *
 *	Called by the generic IO system to write data in buf to transform.
 *	The transform writes the result to the underlying channel.
 *
 * Returns:
 *	Total bytes written or -1 for an error along with a POSIX error
 *	code in errorCodePtr. Use EAGAIN for nonblocking and can't write data.
 *
 * Side effects:
 *	Get data from buf and update digest
 *
 *----------------------------------------------------------------------
 */
 int DigestOutputProc(ClientData clientData, const char *buf, int toWrite, int *errorCodePtr) {
    DigestState *statePtr = (DigestState *) clientData;
    *errorCodePtr = 0;

    /* Abort if nothing to process */
    if (toWrite <= 0 || statePtr->self == (Tcl_Channel) NULL) {
	return 0;
    }

    /* Update hash function */
    if (toWrite > 0 && !DigestUpdate(statePtr, buf, (size_t) toWrite, 0)) {
	Tcl_SetChannelError(statePtr->self, Tcl_ObjPrintf("Update failed: %s", REASON()));
	*errorCodePtr = EINVAL;
	return 0;
    }
    return toWrite;
}

/*
 *----------------------------------------------------------------------
 *
 * DigestSetOptionProc --
 *
 *	Called by the generic IO system to set channel option name to value.
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR if failed along with an error
 *	message in interp and Tcl_SetErrno.
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

    /* Abort if no channel */
    if (statePtr->self == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Delegate options downstream */
    parent = Tcl_GetStackedChannel(statePtr->self);
    setOptionProc = Tcl_ChannelSetOptionProc(Tcl_GetChannelType(parent));
    if (setOptionProc != NULL) {
	return (*setOptionProc)(Tcl_GetChannelInstanceData(parent), interp, optionName, optionValue);
    } else {
	Tcl_SetErrno(EINVAL);
	return Tcl_BadChannelOption(interp, optionName, NULL);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * DigestGetOptionProc --
 *
 *	Called by the generic IO system to get channel option name's value.
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR if failed along with an error
 *	message in interp and Tcl_SetErrno.
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

    /* Abort if no channel */
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
    } else {
	Tcl_SetErrno(EINVAL);
	return Tcl_BadChannelOption(interp, optionName, NULL);
    }
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

    /* Abort if no channel */
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
 *	Nothing (can't return error messages)
 *
 * Side effects:
 *	Configure notifier so future events on the channel will be seen by Tcl.
 *
 *----------------------------------------------------------------------
 */
void DigestWatchProc(ClientData clientData, int mask) {
    DigestState *statePtr = (DigestState *) clientData;
    Tcl_Channel parent;
    Tcl_DriverWatchProc *watchProc;

    /* Abort if no channel */
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
 *	TCL_OK for success or TCL_ERROR for error or if not supported. If
 *	direction is TCL_READABLE, sets handlePtr to the handle used for
 *	input, or if TCL_WRITABLE sets to the handle used for output.
 *
 * Side effects:
 *	None
 *
 *----------------------------------------------------------------------
 */
int DigestGetHandleProc(ClientData clientData, int direction, ClientData *handlePtr) {
    DigestState *statePtr = (DigestState *) clientData;
    Tcl_Channel parent;

    /* Abort if no channel */
    if (statePtr->self == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    parent = Tcl_GetStackedChannel(statePtr->self);
    return Tcl_GetChannelHandle(parent, direction, handlePtr);
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
 * DigestChannelHandler --
 *
 *	Create a stacked channel for a message digest transformation.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Adds transform to channel and sets result to channel id or error message.
 *
 *----------------------------------------------------------------------
 */
static int
DigestChannelHandler(Tcl_Interp *interp, const char *channel, const EVP_MD *md,
	const EVP_CIPHER *cipher, int format, Tcl_Obj *keyObj, EVP_MAC *mac) {
    int mode; /* OR-ed combination of TCL_READABLE and TCL_WRITABLE */
    Tcl_Channel chan;
    DigestState *statePtr;

    /* Validate args */
    if (channel == (const char *) NULL) {
	return TCL_ERROR;
    }

    /* Get channel Id */
    chan = Tcl_GetChannel(interp, channel, &mode);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);

    /* Create state data structure */
    if ((statePtr = DigestStateNew(interp, format)) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }
    statePtr->self = chan;
    statePtr->mode = mode;

    /* Initialize hash function */
    if (DigestInitialize(interp, statePtr, md, cipher, keyObj, mac) != TCL_OK) {
	return TCL_ERROR;
    }

    /* Configure channel */
    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
    if (Tcl_GetChannelBufferSize(chan) < EVP_MAX_MD_SIZE * 2) {
	Tcl_SetChannelBufferSize(chan, EVP_MAX_MD_SIZE * 2);
    }

    /* Stack channel, abort for error */
    statePtr->self = Tcl_StackChannel(interp, &digestChannelType, (ClientData) statePtr, mode, chan);
    if (statePtr->self == (Tcl_Channel) NULL) {
	DigestStateFree(statePtr);
	return TCL_ERROR;
    }

    /* Set result to channel Id */
    Tcl_SetResult(interp, (char *) Tcl_GetChannelName(chan), TCL_VOLATILE);
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * Unstack Channel --
 *
 *	This function removes the stacked channel from the top of the
 *	channel stack if it is a digest channel.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Removes transform from channel or sets result to error message.
 *
 *----------------------------------------------------------------------
 */
static int
DigestUnstackObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Channel chan;
    int mode; /* OR-ed combination of TCL_READABLE and TCL_WRITABLE  */

    /* Validate arg count */
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channelId");
	return TCL_ERROR;
    }

    /* Get channel */
    chan = Tcl_GetChannel(interp, Tcl_GetStringFromObj(objv[1], NULL), &mode);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);

    /* Check if digest channel */
    if (Tcl_GetChannelType(chan) != &digestChannelType) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
	    "\": not a digest channel", NULL);
	Tcl_SetErrorCode(interp, "TLS", "UNSTACK", "CHANNEL", "INVALID", (char *) NULL);
	return TCL_ERROR;
    }

    /* Pop transform from channel */
    return Tcl_UnstackChannel(interp, chan);
    	clientData = clientData;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestInstanceObjCmd --
 *
 *	Handler for digest command instances. Used to add data to hash
 *	function or retrieve message digest.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Adds data to hash or returns message digest
 *
 *-------------------------------------------------------------------
 */
int DigestInstanceObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    DigestState *statePtr = (DigestState *) clientData;
    int fn, len = 0;
    char *buf = NULL;
    static const char *instance_fns [] = { "finalize", "update", NULL };

    /* Validate arg count */
    if (objc < 2 || objc > 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "function ?data?");
	return TCL_ERROR;
    }

    /* Get function */
    if (Tcl_GetIndexFromObj(interp, objv[1], instance_fns, "function", 0, &fn) != TCL_OK) {
	return TCL_ERROR;
    }

    /* Do function */
    if (fn) {
	/* Get data or return error if none */
	if (objc == 3) {
	    buf = Tcl_GetByteArrayFromObj(objv[2], &len);
	} else {
	    Tcl_WrongNumArgs(interp, 1, objv, "update data");
	    return TCL_ERROR;
	}

	/* Update hash function */
	if (!DigestUpdate(statePtr, buf, (size_t) len, 1)) {
	    return TCL_ERROR;
	}

    } else {
	/* Finalize hash function and calculate message digest */
	if (DigestFinalize(interp, statePtr, NULL) != TCL_OK) {
	    return TCL_ERROR;
	}

	Tcl_DeleteCommandFromToken(interp, statePtr->token);
    }
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * DigestCommandDeleteHandler --
 *
 *	 Callback to clean-up when digest instance command is deleted.
 *
 * Returns:
 *	Nothing
 *
 * Side effects:
 *	Destroys state info structure
 *
 *-------------------------------------------------------------------
 */
void DigestCommandDeleteHandler(ClientData clientData) {
    DigestState *statePtr = (DigestState *) clientData;

    /* Clean-up */
    DigestStateFree(statePtr);
}

/*
 *-------------------------------------------------------------------
 *
 * DigestCommandHandler --
 *
 *	 Create command to allow user to add data to hash function.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Creates command or error message
 *
 *-------------------------------------------------------------------
 */
int DigestCommandHandler(Tcl_Interp *interp, Tcl_Obj *cmdObj, const EVP_MD *md,
	const EVP_CIPHER *cipher, int format, Tcl_Obj *keyObj, EVP_MAC *mac) {
    DigestState *statePtr;
    char *cmdName = Tcl_GetStringFromObj(cmdObj, NULL);

    /* Create state data structure */
    if ((statePtr = DigestStateNew(interp, format)) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Initialize hash function */
    if (DigestInitialize(interp, statePtr, md, cipher, keyObj, mac) != TCL_OK) {
	return TCL_ERROR;
    }

    /* Create instance command */
    statePtr->token = Tcl_CreateObjCommand(interp, cmdName, DigestInstanceObjCmd,
	(ClientData) statePtr, DigestCommandDeleteHandler);

    /* Return command name */
    Tcl_SetObjResult(interp, cmdObj);
    return TCL_OK;
}


/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestDataHandler --
 *
 *	Return message digest for data using user specified hash function.
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
DigestDataHandler(Tcl_Interp *interp, Tcl_Obj *dataObj, const EVP_MD *md,
	const EVP_CIPHER *cipher, int format, Tcl_Obj *keyObj, EVP_MAC *mac) {
    char *data;
    int data_len;
    DigestState *statePtr;

    /* Get data */
    data = Tcl_GetByteArrayFromObj(dataObj, &data_len);
    if (data == NULL) {
	Tcl_SetResult(interp, "No data", NULL);
	return TCL_ERROR;
    }

    /* Create state data structure */
    if ((statePtr = DigestStateNew(interp, format)) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Calc Digest, abort for error */
    if (DigestInitialize(interp, statePtr, md, cipher, keyObj, mac) != TCL_OK ||
	DigestUpdate(statePtr, data, (size_t) data_len, 1) == 0 ||
	DigestFinalize(interp, statePtr, NULL) != TCL_OK) {
	DigestStateFree(statePtr);
	return TCL_ERROR;
    }

    /* Clean-up */
    DigestStateFree(statePtr);
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestFileHandler --
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
int DigestFileHandler(Tcl_Interp *interp, Tcl_Obj *filename, const EVP_MD *md,
	const EVP_CIPHER *cipher, int format, Tcl_Obj *keyObj, EVP_MAC *mac) {
    DigestState *statePtr;
    Tcl_Channel chan = NULL;
    unsigned char buf[BUFFER_SIZE];
    int res = TCL_OK, len;

    /* Create state data structure */
    if ((statePtr = DigestStateNew(interp, format)) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Open file channel, abort for error */
    chan = Tcl_FSOpenFileChannel(interp, filename, "rb", 0444);
    if (chan == (Tcl_Channel) NULL) {
	DigestStateFree(statePtr);
	return TCL_ERROR;
    }

    /* Configure channel */
    if ((res = Tcl_SetChannelOption(interp, chan, "-translation", "binary")) == TCL_ERROR) {
	goto done;
    }
    Tcl_SetChannelBufferSize(chan, BUFFER_SIZE);

    /* Initialize hash function */
    if ((res = DigestInitialize(interp, statePtr, md, cipher, keyObj, mac)) != TCL_OK) {
	goto done;
    }

    /* Read file data and update hash function */
    while (!Tcl_Eof(chan)) {
	len = Tcl_ReadRaw(chan, (char *) buf, BUFFER_SIZE);
	if (len > 0) {
	    if (!DigestUpdate(statePtr, &buf[0], (size_t) len, 1)) {
		res = TCL_ERROR;
		goto done;
	    }
	}
    }

    /* Finalize hash function and calculate message digest */
    res = DigestFinalize(interp, statePtr, NULL);

done:
    /* Close channel */
    if (Tcl_Close(interp, chan) == TCL_ERROR) {
	res = TCL_ERROR;
    }

    /* Clean-up */
    DigestStateFree(statePtr);
    return res;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * GetDigest -- Get message digest
 *
 * Returns:
 *	EVP_MD * or NULL
 *
 *-------------------------------------------------------------------
 */
EVP_MD *GetDigest(Tcl_Interp *interp, Tcl_Obj *objPtr, int *format) {
    const EVP_MD *md = NULL;
    char *digestName = Tcl_GetStringFromObj(objPtr, NULL);

    if (digestName != NULL) {
	md = EVP_get_digestbyname(digestName);
	if (md == NULL) {
	    Tcl_AppendResult(interp, "Invalid digest \"", digestName, "\"", NULL);
	    return NULL;
	} else if (md == EVP_shake128() || md == EVP_shake256()) {
	    *format |= IS_XOF;
	}
    } else {
	Tcl_AppendResult(interp, "No digest specified", NULL);
	return NULL;
    }
    return md;
}

/*
 *-------------------------------------------------------------------
 *
 * GetCipher -- Get cipher
 *
 * Returns:
 *	EVP_CIPHER * or NULL
 *
 *-------------------------------------------------------------------
 */
EVP_CIPHER *GetCipher(Tcl_Interp *interp, Tcl_Obj *objPtr, int *type) {
    const EVP_CIPHER *cipher = NULL;
    char *cipherName = Tcl_GetStringFromObj(objPtr, NULL);

    if (cipherName != NULL) {
	cipher = EVP_get_cipherbyname(cipherName);
	*type = TYPE_CMAC;
	if (cipher == NULL) {
	    Tcl_AppendResult(interp, "Invalid cipher \"", cipherName, "\"", NULL);
	    return NULL;
	}
    } else {
	Tcl_AppendResult(interp, "No cipher specified", NULL);
	return NULL;
    }
    return cipher;
}

/*
 *-------------------------------------------------------------------
 *
 * GetKey -- Get key
 *
 * Returns:
 *	unsigned char * or NULL
 *
 *-------------------------------------------------------------------
 */
unsigned char *GetKey(Tcl_Interp *interp, Tcl_Obj *objPtr, int *type) {
    unsigned char *key = Tcl_GetByteArrayFromObj(objPtr, NULL);

    if (key == NULL) {
	Tcl_AppendResult(interp, "No key specified", NULL);
	return NULL;
    }
    if (*type == TYPE_MD) {
	*type = TYPE_HMAC;
    }
    return key;
}

/*
 *-------------------------------------------------------------------
 *
 * GetMAC -- Get MAC
 *
 * Returns:
 *	EVP_MAC * or NULL
 *
 *-------------------------------------------------------------------
 */
EVP_MAC *GetMAC(Tcl_Interp *interp, Tcl_Obj *objPtr, int *type) {
    EVP_MAC *mac = NULL;
    char *macName = Tcl_GetStringFromObj(objPtr, NULL);

    if (macName != NULL) {
	if (strcmp(macName, "cmac") == 0) {
	    *type = TYPE_CMAC;
	} else if (strcmp(macName, "hmac") == 0) {
	    *type = TYPE_HMAC;
	} else {
	    Tcl_AppendResult(interp, "Invalid MAC \"", macName, "\"", NULL);
	    return NULL;
	}
	mac = (void *) macName;
    } else {
	Tcl_AppendResult(interp, "No MAC specified", NULL);
	return NULL;
    }
    return mac;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * DigestMain --
 *
 *	Return message digest or Message Authentication Code (MAC) of
 *	data using user specified hash function.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to message digest or error message
 *
 *-------------------------------------------------------------------
 */
static int DigestMain(int type, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int idx, start = 1, format = HEX_FORMAT, res = TCL_OK;
    Tcl_Obj *cipherObj = NULL, *cmdObj = NULL, *dataObj = NULL, *digestObj = NULL;
    Tcl_Obj *fileObj = NULL, *keyObj = NULL, *macObj = NULL;
    const char *channel = NULL, *opt;
    const EVP_MD *md = NULL;
    const EVP_CIPHER *cipher = NULL;
    EVP_MAC *mac = NULL;

    /* Clear interp result */
    Tcl_ResetResult(interp);

    /* Validate arg count */
    if (objc < 3 || objc > 12) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-bin|-hex? ?-cipher name? ?-digest name? ?-key key? ?-mac name? [-channel chan | -command cmdName | -file filename | ?-data? data]");
	return TCL_ERROR;
    }

    /* Special case of first arg is digest, cipher, or mac */
    opt = Tcl_GetStringFromObj(objv[start], NULL);
    if (opt[0] != '-') {
	if (type == TYPE_MD || type == TYPE_HMAC) {
	    digestObj = objv[start];
	    start++;
	} else if (type == TYPE_CMAC) {
	    cipherObj = objv[start];
	    start++;
	} else if (type == TYPE_MAC) {
	    macObj = objv[start];
	    start++;
	}
    }

    /* Get options */
    for (idx = start; idx < objc; idx++) {
	opt = Tcl_GetStringFromObj(objv[idx], NULL);

	if (opt[0] != '-') {
	    break;
	}

	OPTFLAG("-bin", format, BIN_FORMAT);
	OPTFLAG("-binary", format, BIN_FORMAT);
	OPTFLAG("-hex", format, HEX_FORMAT);
	OPTFLAG("-hexadecimal", format, HEX_FORMAT);
	OPTSTR("-chan", channel);
	OPTSTR("-channel", channel);
	OPTOBJ("-cipher", cipherObj);
	OPTOBJ("-command", cmdObj);
	OPTOBJ("-data", dataObj);
	OPTOBJ("-digest", digestObj);
	OPTOBJ("-file", fileObj);
	OPTOBJ("-filename", fileObj);
	OPTOBJ("-key", keyObj);
	OPTOBJ("-mac", macObj);

	OPTBAD("option", "-bin, -channel, -cipher, -command, -data, -digest, -file, -filename, -hex, -key, or -mac");
	return TCL_ERROR;
    }

    /* If only 1 arg left, it's the data */
    if (idx < objc && dataObj == NULL) {
	dataObj = objv[idx];
    }

    /* Get cipher */
    if (cipherObj != NULL) {
	if ((cipher = GetCipher(interp, cipherObj, &type)) == NULL) {
	    return TCL_ERROR;
	}
    } else if (type == TYPE_CMAC) {
	Tcl_AppendResult(interp, "No cipher specified", NULL);
	return TCL_ERROR;
    }

    /* Get message digest */
    if (digestObj != NULL) {
	if ((md = GetDigest(interp, digestObj, &format)) == NULL) {
	    return TCL_ERROR;
	}
    } else if (type == TYPE_MD || type == TYPE_HMAC) {
	Tcl_AppendResult(interp, "No digest specified", NULL);
	return TCL_ERROR;
    }

    /* Get key */
    if (keyObj != NULL) {
	if (GetKey(interp, keyObj, &type) == NULL) {
	    return TCL_ERROR;	
	}
    } else if (type != TYPE_MD) {
	Tcl_AppendResult(interp, "No key specified", NULL);
	return TCL_ERROR;
    }

    /* Get MAC */
    if (macObj != NULL) {
	if ((mac = GetMAC(interp, macObj, &type)) == NULL) {
	    return TCL_ERROR;
	}
    } else if (type == TYPE_MAC) {
	Tcl_AppendResult(interp, "No MAC specified", NULL);
	return TCL_ERROR;
    }

    /* Calc digest on file, stacked channel, using instance command, or data blob */
    if (fileObj != NULL) {
	res = DigestFileHandler(interp, fileObj, md, cipher, format | type, keyObj, mac);
    } else if (channel != NULL) {
	res = DigestChannelHandler(interp, channel, md, cipher, format | type, keyObj, mac);
    } else if (cmdObj != NULL) {
	res = DigestCommandHandler(interp, cmdObj, md, cipher, format | type, keyObj, mac);
    } else if (dataObj != NULL) {
	res = DigestDataHandler(interp, dataObj, md, cipher, format | type, keyObj, mac);
    } else {
	Tcl_AppendResult(interp, "No operation specified: Use -channel, -command, -data, or -file option", NULL);
	res = TCL_ERROR;
    }
    return res;
}

/*
 *-------------------------------------------------------------------
 *
 * Message Digest and Message Authentication Code Commands --
 *
 *	Return Message Digest (MD) or Message Authentication Code (MAC).
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to message digest or error message
 *
 *-------------------------------------------------------------------
 */
static int MdObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return DigestMain(TYPE_MD, interp, objc, objv);
}

static int CMACObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return DigestMain(TYPE_CMAC, interp, objc, objv);
}

static int HMACObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return DigestMain(TYPE_HMAC, interp, objc, objv);
}

static int MACObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    return DigestMain(TYPE_MAC, interp, objc, objv);
}

/*
 *-------------------------------------------------------------------
 *
 * Message Digest Convenience Commands --
 *
 *	Convenience commands for select message digests.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result to message digest or error message
 *
 *-------------------------------------------------------------------
 */
 #define validate_argc(objc, objv) { \
    if (objc != 2) { \
	Tcl_WrongNumArgs(interp, 1, objv, "data"); \
	return TCL_ERROR; \
    } \
}
 
int MD4ObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    validate_argc(objc, objv);
    return DigestDataHandler(interp, objv[1], EVP_md4(), NULL, HEX_FORMAT | TYPE_MD, NULL, NULL);
}

int MD5ObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    validate_argc(objc, objv);
    return DigestDataHandler(interp, objv[1], EVP_md5(), NULL, HEX_FORMAT | TYPE_MD, NULL, NULL);
}

int SHA1ObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    validate_argc(objc, objv);
    return DigestDataHandler(interp, objv[1], EVP_sha1(), NULL, HEX_FORMAT | TYPE_MD, NULL, NULL);
}

int SHA256ObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    validate_argc(objc, objv);
    return DigestDataHandler(interp, objv[1], EVP_sha256(), NULL, HEX_FORMAT | TYPE_MD, NULL, NULL);
}

int SHA512ObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    validate_argc(objc, objv);
    return DigestDataHandler(interp, objv[1], EVP_sha512(), NULL, HEX_FORMAT | TYPE_MD, NULL, NULL);
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
    Tcl_CreateObjCommand(interp, "tls::digest", MdObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::md", MdObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::cmac", CMACObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::hmac", HMACObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::mac", MACObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::md4", MD4ObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::md5", MD5ObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::sha1", SHA1ObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::sha256", SHA256ObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::sha512", SHA512ObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::unstack", DigestUnstackObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}

