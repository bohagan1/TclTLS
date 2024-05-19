/*
 * Encryption Functions Module
 *
 * This module provides commands that can be used to encrypt or decrypt data.
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#endif

/* Macros */
#define BUFFER_SIZE	32768
#define CHAN_EOF	0x10
#define READ_DELAY	5

/* Encryption functions */
#define TYPE_MD		0x010
#define TYPE_HMAC	0x020
#define TYPE_CMAC	0x040
#define TYPE_MAC	0x080
#define TYPE_ENCRYPT	0x100
#define TYPE_DECRYPT	0x200
#define TYPE_SIGN	0x400
#define TYPE_VERIFY	0x800

/*******************************************************************/

/*
 * This structure defines the per-instance state of a encrypt operation.
 */
typedef struct EncryptState {
	Tcl_Channel self;	/* This socket channel */
	Tcl_TimerToken timer;	/* Timer for read events */

	int flags;		/* Chan config flags */
	int watchMask;		/* Current WatchProc mask */
	int mode;		/* Current mode of parent channel */
	int type;		/* Operation type */

	Tcl_Interp *interp;	/* Current interpreter */
	EVP_CIPHER_CTX *ctx;	/* Cipher Context */
	Tcl_Command token;	/* Command token */
} EncryptState;


/*
 *-------------------------------------------------------------------
 *
 * EncryptStateNew --
 *
 *	This function creates a per-instance state data structure
 *
 * Returns:
 *	State structure pointer
 *
 * Side effects:
 *	Creates structure
 *
 *-------------------------------------------------------------------
 */
EncryptState *EncryptStateNew(Tcl_Interp *interp, int type) {
    EncryptState *statePtr = (EncryptState *) ckalloc((unsigned) sizeof(EncryptState));

    if (statePtr != NULL) {
	memset(statePtr, 0, sizeof(EncryptState));
	statePtr->self	= NULL;		/* This socket channel */
	statePtr->timer = NULL;		/* Timer to flush data */
	statePtr->flags = 0;		/* Chan config flags */
	statePtr->watchMask = 0;	/* Current WatchProc mask */
	statePtr->mode	= 0;		/* Current mode of parent channel */
	statePtr->type = type;		/* Operation type */
	statePtr->interp = interp;	/* Current interpreter */
	statePtr->ctx = NULL;		/* Cipher Context */
	statePtr->token = NULL;		/* Command token */
    }
    return statePtr;
}

/*
 *-------------------------------------------------------------------
 *
 * EncryptStateFree --
 *
 *	This function deletes a state data structure
 *
 * Returns:
 *	Nothing
 *
 * Side effects:
 *	Removes structure
 *
 *-------------------------------------------------------------------
 */
void EncryptStateFree(EncryptState *statePtr) {
    if (statePtr == (EncryptState *) NULL) {
	return;
    }

    /* Remove pending timer */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
    }

    /* Free context structures */
    if (statePtr->ctx != (EVP_CIPHER_CTX *) NULL) {
	EVP_CIPHER_CTX_free(statePtr->ctx);
    }
    ckfree(statePtr);
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * EncryptInitialize --
 *
 *	Initialize an encryption function
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
int EncryptInitialize(Tcl_Interp *interp, int type, EVP_CIPHER_CTX **ctx,
	Tcl_Obj *cipherObj, Tcl_Obj *keyObj, Tcl_Obj *ivObj, int padding) {
    const EVP_CIPHER *cipher;
    void *keyString = NULL, *ivString = NULL;
    Tcl_Size key_len = 0, iv_len = 0;
    int res, max;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

    dprintf("Called");

    /* Init buffers */
    memset(key, 0, EVP_MAX_KEY_LENGTH);
    memset(iv, 0, EVP_MAX_IV_LENGTH);

    /* Get cipher */
    cipher = Util_GetCipher(interp, cipherObj, 1);
    if (cipher == NULL) {
	return TCL_ERROR;
    }

    /*  Get key - Only support internally defined cipher lengths.
	Custom ciphers can be up to size_t bytes. */
    max = EVP_CIPHER_key_length(cipher);
    keyString = Util_GetKey(interp, keyObj, &key_len, "key", max, 0);
    if (keyString != NULL) {
	memcpy((void *) key, keyString, (size_t) key_len);
    } else if (keyObj != NULL)  {
	return TCL_ERROR;
    }

    /*  Get IV */
    max = EVP_CIPHER_iv_length(cipher);
    ivString = Util_GetIV(interp, ivObj, &iv_len, max, 0);
    if (ivString != NULL) {
	memcpy((void *) iv, ivString, (size_t) iv_len);
    } else if (ivObj != NULL) {
	return TCL_ERROR;
    }

    /* Create context */
    if((*ctx = EVP_CIPHER_CTX_new()) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Initialize the operation */
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptInit_ex(*ctx, cipher, NULL, NULL, NULL);
    } else {
	res = EVP_DecryptInit_ex(*ctx, cipher, NULL, NULL, NULL);
    }

    if(!res) {
	Tcl_AppendResult(interp, "Initialize failed: ", GET_ERR_REASON(), (char *) NULL);
	return TCL_ERROR;
    }

    /* Turn off PKCS#7 padding */
    if (!padding) {
	EVP_CIPHER_CTX_set_padding(*ctx, padding);
    }

    /* Set key and IV */
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptInit_ex(*ctx, NULL, NULL, key, iv);
    } else {
	res = EVP_DecryptInit_ex(*ctx, NULL, NULL, key, iv);
    }

    if(!res) {
	Tcl_AppendResult(interp, "Set key and IV failed: ", GET_ERR_REASON(), (char *) NULL);
	return TCL_ERROR;
    }

    /* Erase buffers */
    memset(key, 0, EVP_MAX_KEY_LENGTH);
    memset(iv, 0, EVP_MAX_IV_LENGTH);
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * EncryptUpdate --
 *
 *	Update an encryption function with data
 *
 * Returns:
 *	1 if successful or 0 for failure
 *
 * Side effects:
 *	Adds encrypted data to buffer or sets result to error message
 *
 *-------------------------------------------------------------------
 */
int EncryptUpdate(Tcl_Interp *interp, int type, EVP_CIPHER_CTX *ctx, unsigned char *out_buf,
	int *out_len, unsigned char *data, Tcl_Size data_len) {
    int res;

    dprintf("Called");

    /* Encrypt/decrypt data */
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptUpdate(ctx, out_buf, out_len, data, (int) data_len);
    } else {
	res = EVP_DecryptUpdate(ctx, out_buf, out_len, data, (int) data_len);
    }

    if (res) {
	return TCL_OK;
    } else {
	Tcl_AppendResult(interp, "Update failed: ", GET_ERR_REASON(), (char *) NULL);
	return TCL_ERROR;
    }
}

/*
 *-------------------------------------------------------------------
 *
 * EncryptFinalize --
 *
 *	Finalize an encryption function
 *
 * Returns:
 *	TCL_OK if successful or TCL_ERROR for failure with result set
 *	to error message.
 *
 * Side effects:
 *	Adds encrypted data to buffer or sets result to error message
 *
 *-------------------------------------------------------------------
 */
int EncryptFinalize(Tcl_Interp *interp, int type, EVP_CIPHER_CTX *ctx, unsigned char *out_buf,
	int *out_len) {
    int res;

    dprintf("Called");

    /* Finalize data */
    if (type == TYPE_ENCRYPT) {
	res = EVP_EncryptFinal_ex(ctx, out_buf, out_len);
    } else {
	res = EVP_DecryptFinal_ex(ctx, out_buf, out_len);
    }

    if (res) {
	return TCL_OK;
    } else {
	Tcl_AppendResult(interp, "Finalize failed: ", GET_ERR_REASON(), (char *) NULL);
	return TCL_ERROR;
    }
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * EncryptBlockModeProc --
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
static int EncryptBlockModeProc(ClientData clientData, int mode) {
    EncryptState *statePtr = (EncryptState *) clientData;

    dprintf("Called");

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
 * EncryptCloseProc --
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
int EncryptCloseProc(ClientData clientData, Tcl_Interp *interp) {
    EncryptState *statePtr = (EncryptState *) clientData;

    dprintf("Called");

    /* Cancel active timer, if any */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
    }

    /* Output remaining data, if any */
    if (!(statePtr->flags & CHAN_EOF)) {
	Tcl_Channel parent = Tcl_GetStackedChannel(statePtr->self);
	int out_len;
	unsigned char out_buf[EVP_MAX_BLOCK_LENGTH];

	/* Finalize function */
	if (EncryptFinalize(interp, statePtr->type, statePtr->ctx, out_buf, &out_len) == TCL_OK) {
	    if (out_len > 0) {
		Tcl_Size len = Tcl_WriteRaw(parent, (const char *) out_buf, (Tcl_Size) out_len);
		if (len < 0) {
		    return Tcl_GetErrno();
		}
	    }
	} else {
	    /* Error */
	}

	statePtr->flags |= CHAN_EOF;
    }

    /* Clean-up */
    EncryptStateFree(statePtr);
    return 0;
}

/*
 * Same as EncryptCloseProc but with individual read and write close control
 */
static int EncryptClose2Proc(ClientData instanceData, Tcl_Interp *interp, int flags) {
    dprintf("Called");

    if ((flags & (TCL_CLOSE_READ | TCL_CLOSE_WRITE)) == 0) {
	return EncryptCloseProc(instanceData, interp);
    }
    return EINVAL;
}

/*
 *----------------------------------------------------------------------
 *
 * EncryptInputProc --
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
int EncryptInputProc(ClientData clientData, char *buf, int toRead, int *errorCodePtr) {
    EncryptState *statePtr = (EncryptState *) clientData;
    Tcl_Channel parent;
    int out_len;
    Tcl_Size read;
    *errorCodePtr = 0;
    char *in_buf;
    
    dprintf("Called");

    /* Abort if nothing to process */
    if (toRead <= 0 || statePtr->self == (Tcl_Channel) NULL) {
	return 0;
    }

    /* Get bytes from underlying channel */
    in_buf = Tcl_Alloc((Tcl_Size) toRead);
    parent = Tcl_GetStackedChannel(statePtr->self);
    read = Tcl_ReadRaw(parent, in_buf, (Tcl_Size) toRead);

    /* Update function */
    if (read > 0) {
	/* Have data - Update function */
	if (EncryptUpdate(statePtr->interp, statePtr->type, statePtr->ctx, (unsigned char *) buf,
		&out_len, (unsigned char *) in_buf, read) == TCL_OK) {
	    /* If have data, put in buf, otherwise tell TCL to try again */
	    if (out_len > 0) {
		read = (Tcl_Size) out_len;
	    } else {
		*errorCodePtr = EAGAIN;
		read = -1;
	    }
	} else {
	    Tcl_SetChannelError(statePtr->self, Tcl_ObjPrintf("Update failed: %s", GET_ERR_REASON()));
	    *errorCodePtr = EINVAL;
	    read = 0;
	}

    } else if (read < 0) {
	/* Error */
	*errorCodePtr = Tcl_GetErrno();

    } else if (!(statePtr->flags & CHAN_EOF)) {
	/* EOF - Finalize function and put any remaining data in buf */
	if (EncryptFinalize(statePtr->interp, statePtr->type, statePtr->ctx, (unsigned char *) buf, &out_len) == TCL_OK) {
	    read = (Tcl_Size) out_len;
	} else {
	    Tcl_SetChannelError(statePtr->self, Tcl_ObjPrintf("Finalize failed: %s", GET_ERR_REASON()));
	    *errorCodePtr = EINVAL;
	    read = 0;
	}

	statePtr->flags |= CHAN_EOF;
    }
    Tcl_Free(in_buf);
    return (int) read;
}

/*
 *----------------------------------------------------------------------
 *
 * EncryptOutputProc --
 *
 *	Called by the generic IO system to write data in buf to transform.
 *	The transform writes the result to the underlying channel.
 *
 * Returns:
 *	Total bytes written or -1 for an error along with a POSIX error
 *	code in errorCodePtr. Use EAGAIN for nonblocking and can't write data.
 *
 * Side effects:
 *	Get data from buf and update encryption
 *
 *----------------------------------------------------------------------
 */
 int EncryptOutputProc(ClientData clientData, const char *buf, int toWrite, int *errorCodePtr) {
    EncryptState *statePtr = (EncryptState *) clientData;
    int write = 0, out_len;
    *errorCodePtr = 0;
    char *out_buf;

    dprintf("Called");

    /* Abort if nothing to process */
    if (toWrite <= 0 || statePtr->self == (Tcl_Channel) NULL) {
	return 0;
    }

    out_buf = Tcl_Alloc((Tcl_Size) toWrite+EVP_MAX_BLOCK_LENGTH);

    /* Update function */
    if (EncryptUpdate(statePtr->interp, statePtr->type, statePtr->ctx, (unsigned char *) out_buf,
	    &out_len, (unsigned char *) buf, (Tcl_Size) toWrite) == TCL_OK) {
	/* If have data, output it, otherwise tell TCL to try again */
	if (out_len > 0) {
	    Tcl_Channel parent = Tcl_GetStackedChannel(statePtr->self);
	    write = (int) Tcl_WriteRaw(parent, (const char *) out_buf, (Tcl_Size) out_len);
	    write = toWrite;
	} else {
	    *errorCodePtr = EAGAIN;
	    write = -1;
	}

    } else {
	Tcl_SetChannelError(statePtr->self, Tcl_ObjPrintf("Update failed: %s", GET_ERR_REASON()));
	*errorCodePtr = EINVAL;
	write = 0;
    }
    Tcl_Free(out_buf);
    return write;
}

/*
 *----------------------------------------------------------------------
 *
 * EncryptSetOptionProc --
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
static int EncryptSetOptionProc(ClientData clientData, Tcl_Interp *interp, const char *optionName,
	const char *optionValue) {
    EncryptState *statePtr = (EncryptState *) clientData;
    Tcl_Channel parent;
    Tcl_DriverSetOptionProc *setOptionProc;

    dprintf("Called");

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
 * EncryptGetOptionProc --
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
static int EncryptGetOptionProc(ClientData clientData, Tcl_Interp *interp, const char *optionName,
	Tcl_DString *optionValue) {
    EncryptState *statePtr = (EncryptState *) clientData;
    Tcl_Channel parent;
    Tcl_DriverGetOptionProc *getOptionProc;

    dprintf("Called");

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
 * EncryptTimerHandler --
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
static void EncryptTimerHandler(ClientData clientData) {
    EncryptState *statePtr = (EncryptState *) clientData;

    dprintf("Called");

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
 * EncryptWatchProc --
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
void EncryptWatchProc(ClientData clientData, int mask) {
    EncryptState *statePtr = (EncryptState *) clientData;
    Tcl_Channel parent;
    Tcl_DriverWatchProc *watchProc;

    dprintf("Called");

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
	statePtr->timer = Tcl_CreateTimerHandler(READ_DELAY, EncryptTimerHandler, (ClientData) statePtr);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * EncryptGetHandleProc --
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
int EncryptGetHandleProc(ClientData clientData, int direction, ClientData *handlePtr) {
    EncryptState *statePtr = (EncryptState *) clientData;
    Tcl_Channel parent;

    dprintf("Called");

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
 * EncryptNotifyProc --
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
int EncryptNotifyProc(ClientData clientData, int interestMask) {
    EncryptState *statePtr = (EncryptState *) clientData;

    dprintf("Called");

    /* Skip timer event as redundant */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
    }
    return interestMask;
}

/*
 *
 * Channel type structure definition for encryption transformations.
 *
 */
static const Tcl_ChannelType encryptChannelType = {
    "encryption",		/* Type name */
    TCL_CHANNEL_VERSION_5,	/* v5 channel */
    EncryptCloseProc,		/* Close proc */
    EncryptInputProc,		/* Input proc */
    EncryptOutputProc,		/* Output proc */
    NULL,			/* Seek proc */
    EncryptSetOptionProc,	/* Set option proc */
    EncryptGetOptionProc,	/* Get option proc */
    EncryptWatchProc,		/* Initialize notifier */
    EncryptGetHandleProc,	/* Get OS handles out of channel */
    EncryptClose2Proc,		/* close2proc */
    EncryptBlockModeProc,	/* Set blocking/nonblocking mode*/
    NULL,			/* Flush proc */
    EncryptNotifyProc,		/* Handling of events bubbling up */
    NULL,			/* Wide seek proc */
    NULL,			/* Thread action */
    NULL			/* Truncate */
};

/*
 *----------------------------------------------------------------------
 *
 * EncryptChannelHandler --
 *
 *	Create a stacked channel for a message encryption transformation.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Adds transform to channel and sets result to channel id or error message.
 *
 *----------------------------------------------------------------------
 */
static int EncryptChannelHandler(Tcl_Interp *interp, int type, const char *channel,
	Tcl_Obj *cipherObj, Tcl_Obj *digestObj, Tcl_Obj *keyObj, Tcl_Obj *ivObj, int padding) {
    int mode; /* OR-ed combination of TCL_READABLE and TCL_WRITABLE */
    Tcl_Channel chan;
    EncryptState *statePtr;

    dprintf("Called");

    /* Validate args */
    if (channel == (const char *) NULL) {
	Tcl_AppendResult(interp, "No channel", (char *) NULL);
	return TCL_ERROR;
    }

    /* Get channel Id */
    chan = Tcl_GetChannel(interp, channel, &mode);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);

    /* Configure channel */
    Tcl_SetChannelOption(interp, chan, "-translation", "binary");

    /* Create state data structure */
    if ((statePtr = EncryptStateNew(interp, type)) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }
    statePtr->self = chan;
    statePtr->mode = mode;

    /* Initialize function */
    if (EncryptInitialize(interp, type, &statePtr->ctx, cipherObj, keyObj, ivObj, padding) != TCL_OK) {
	EncryptStateFree(statePtr);
	return TCL_ERROR;
    }

    /* Stack channel */
    statePtr->self = Tcl_StackChannel(interp, &encryptChannelType, (ClientData) statePtr, mode, chan);
    if (statePtr->self == (Tcl_Channel) NULL) {
	EncryptStateFree(statePtr);
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
 *	channel stack if it is a encryption channel.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Removes transform from channel or sets result to error message.
 *
 *----------------------------------------------------------------------
 */
static int EncryptUnstackObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Channel chan;
    int mode; /* OR-ed combination of TCL_READABLE and TCL_WRITABLE  */
    (void) clientData;

    dprintf("Called");

    /* Validate arg count */
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channelId");
	return TCL_ERROR;
    }

    /* Get channel */
    chan = Tcl_GetChannel(interp, Tcl_GetString(objv[1]), &mode);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);

    /* Check if encryption channel */
    if (Tcl_GetChannelType(chan) != &encryptChannelType) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
	    "\": not a encryption channel", (char *) NULL);
	Tcl_SetErrorCode(interp, "TLS", "UNSTACK", "CHANNEL", "INVALID", (char *) NULL);
	return TCL_ERROR;
    }

    /* Pop transform from channel */
    return Tcl_UnstackChannel(interp, chan);
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * EncryptInstanceObjCmd --
 *
 *	Handler for encrypt/decrypt command instances. Used to update
 *	and finalize data for encrypt/decrypt function.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Adds data to encrypt/decrypt function
 *
 *-------------------------------------------------------------------
 */
int EncryptInstanceObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    EncryptState *statePtr = (EncryptState *) clientData;
    int fn, out_len;
    Tcl_Size data_len = 0;
    unsigned char *data = NULL;
    Tcl_Obj *resultObj;
    unsigned char *out_buf;
    static const char *instance_fns [] = { "finalize", "update", NULL };

    dprintf("Called");

    /* Validate arg count */
    if (objc < 2 || objc > 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "function ?data?");
	return TCL_ERROR;
    }

    /* Get function */
    if (Tcl_GetIndexFromObj(interp, objv[1], instance_fns, "function", 0, &fn) != TCL_OK) {
	return TCL_ERROR;
    }

    /* Allocate storage for result. Size should be data size + block size. */
    resultObj = Tcl_NewObj();
    out_buf = Tcl_SetByteArrayLength(resultObj, data_len+EVP_MAX_BLOCK_LENGTH);
    if (resultObj == NULL || out_buf == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	Tcl_DecrRefCount(resultObj);
	return TCL_ERROR;
    }

    /* Do function */
    if (fn) {
	/* Get data or return error if none */
	if (objc == 3) {
	    data = Tcl_GetByteArrayFromObj(objv[2], &data_len);
	} else {
	    Tcl_WrongNumArgs(interp, 1, objv, "update data");
	    Tcl_DecrRefCount(resultObj);
	    return TCL_ERROR;
	}

	/* Update function */
	if (EncryptUpdate(interp, statePtr->type, statePtr->ctx, out_buf, &out_len, data, data_len) == TCL_OK) {
	    out_buf = Tcl_SetByteArrayLength(resultObj, (Tcl_Size) out_len);
	    Tcl_SetObjResult(interp, resultObj);
	} else {
	    Tcl_DecrRefCount(resultObj);
	    return TCL_ERROR;
	}

    } else {
	/* Finalize function */
	if (EncryptFinalize(interp, statePtr->type, statePtr->ctx, out_buf, &out_len) == TCL_OK) {
	    out_buf = Tcl_SetByteArrayLength(resultObj, (Tcl_Size) out_len);
	    Tcl_SetObjResult(interp, resultObj);
	} else {
	    Tcl_DecrRefCount(resultObj);
	    return TCL_ERROR;
	}

	/* Clean-up */
	Tcl_DeleteCommandFromToken(interp, statePtr->token);
    }
    return TCL_OK;
}

/*
 *-------------------------------------------------------------------
 *
 * EncryptCommandDeleteHandler --
 *
 *	 Callback to clean-up when encrypt/decrypt command is deleted.
 *
 * Returns:
 *	Nothing
 *
 * Side effects:
 *	Destroys state info structure
 *
 *-------------------------------------------------------------------
 */
void EncryptCommandDeleteHandler(ClientData clientData) {
    EncryptState *statePtr = (EncryptState *) clientData;

    dprintf("Called");

    /* Clean-up */
    EncryptStateFree(statePtr);
}

/*
 *-------------------------------------------------------------------
 *
 * EncryptCommandHandler --
 *
 *	 Create command to add data to encrypt/decrypt function.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Creates command or error message
 *
 *-------------------------------------------------------------------
 */
int EncryptCommandHandler(Tcl_Interp *interp, int type, Tcl_Obj *cmdObj, Tcl_Obj *cipherObj,
	Tcl_Obj *digestObj, Tcl_Obj *keyObj, Tcl_Obj *ivObj, int padding) {
    EncryptState *statePtr;
    char *cmdName = Tcl_GetString(cmdObj);

    dprintf("Called");

    if ((statePtr = EncryptStateNew(interp, type)) == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Initialize function */
    if (EncryptInitialize(interp, type, &statePtr->ctx, cipherObj, keyObj, ivObj, padding) != TCL_OK) {
	EncryptStateFree(statePtr);
	return TCL_ERROR;
    }

    /* Create instance command */
    statePtr->token = Tcl_CreateObjCommand(interp, cmdName, EncryptInstanceObjCmd,
	(ClientData) statePtr, EncryptCommandDeleteHandler);

    /* Return command name */
    Tcl_SetObjResult(interp, cmdObj);
    return TCL_OK;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * EncryptDataHandler --
 *
 *	Perform encryption function on a block of data and return result.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result or error message
 *
 *-------------------------------------------------------------------
 */
int EncryptDataHandler(Tcl_Interp *interp, int type, Tcl_Obj *dataObj, Tcl_Obj *cipherObj,
	Tcl_Obj *digestObj, Tcl_Obj *keyObj, Tcl_Obj *ivObj, int padding) {
    EVP_CIPHER_CTX *ctx = NULL;
    int out_len = 0, len = 0, res = TCL_OK;
    Tcl_Size data_len = 0;
    unsigned char *data, *out_buf;
    Tcl_Obj *resultObj;

    dprintf("Called");

    /* Get data */
    if (dataObj != NULL) {
	data = Tcl_GetByteArrayFromObj(dataObj, &data_len);
    } else {
	Tcl_AppendResult(interp, "No data", (char *) NULL);
	return TCL_ERROR;
    }

    /* Allocate storage for result. Size should be data size + block size. */
    resultObj = Tcl_NewObj();
    out_buf = Tcl_SetByteArrayLength(resultObj, data_len+EVP_MAX_BLOCK_LENGTH);
    if (resultObj == NULL || out_buf == NULL) {
	Tcl_AppendResult(interp, "Memory allocation error", (char *) NULL);
	return TCL_ERROR;
    }

    /* Perform operation */
    if (EncryptInitialize(interp, type, &ctx, cipherObj, keyObj, ivObj, padding) != TCL_OK ||
	EncryptUpdate(interp, type, ctx, out_buf, &out_len, data, data_len) != TCL_OK ||
	EncryptFinalize(interp, type, ctx, out_buf+out_len, &len) != TCL_OK) {
	res = TCL_ERROR;
	goto done;
    }
    out_len += len;

done:
    /* Set output result */
    if (res == TCL_OK) {
	out_buf = Tcl_SetByteArrayLength(resultObj, (Tcl_Size) out_len);
	Tcl_SetObjResult(interp, resultObj);
    } else {
	Tcl_DecrRefCount(resultObj);
	/* Result is error message */
    }

    /* Clean up */
    if (ctx != NULL) {
	EVP_CIPHER_CTX_free(ctx);
    }
    return res;
}

/*******************************************************************/

/*
 *-------------------------------------------------------------------
 *
 * EncryptFileHandler --
 *
 *	Perform encryption function on a block of data and return result.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Encrypts or decrypts inFile data to outFile and sets result to
 *	size of outFile, or an error message.
 *
 *-------------------------------------------------------------------
 */
int EncryptFileHandler(Tcl_Interp *interp, int type, Tcl_Obj *inFileObj, Tcl_Obj *outFileObj,
	Tcl_Obj *cipherObj, Tcl_Obj *digestObj, Tcl_Obj *keyObj, Tcl_Obj *ivObj, int padding) {
    EVP_CIPHER_CTX *ctx = NULL;
    int total = 0, res, out_len = 0, len;
    Tcl_Channel in = NULL, out = NULL;
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE+EVP_MAX_BLOCK_LENGTH];

    dprintf("Called");

    /* Open input file */
    if ((in = Tcl_FSOpenFileChannel(interp, inFileObj, "rb", 0444)) == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Open output file */
    if ((out = Tcl_FSOpenFileChannel(interp, outFileObj, "wb", 0644)) == (Tcl_Channel) NULL) {
	Tcl_Close(interp, in);
	return TCL_ERROR;
    }

    /* Initialize operation */
    if ((res = EncryptInitialize(interp, type, &ctx, cipherObj, keyObj, ivObj, padding)) != TCL_OK) {
	goto done;
    }

    /* Read file data from inFile, encrypt/decrypt it, then output to outFile */
    while (!Tcl_Eof(in)) {
	Tcl_Size read = Tcl_ReadRaw(in, (char *) in_buf, BUFFER_SIZE);
	if (read > 0) {
	    if ((res = EncryptUpdate(interp, type, ctx, out_buf, &out_len, in_buf, read)) == TCL_OK) {
		if (out_len > 0) {
		    len = (int) Tcl_WriteRaw(out, (const char *) out_buf, (Tcl_Size) out_len);
		    if (len >= 0) {
			total += len;
		    } else {
			Tcl_AppendResult(interp, "Write error: ", Tcl_ErrnoMsg(Tcl_GetErrno()), (char *) NULL);
			res = TCL_ERROR;
			goto done;
		    }
		}
	    } else {
		goto done;
	    }
	} else if (read < 0) {
	    Tcl_AppendResult(interp, "Read error: ", Tcl_ErrnoMsg(Tcl_GetErrno()), (char *) NULL);
	    res = TCL_ERROR;
	    goto done;
	}
    }

    /* Finalize data and write any remaining data in block */
    if ((res = EncryptFinalize(interp, type, ctx, out_buf, &out_len)) == TCL_OK) {
	if (out_len > 0) {
	    len = (int) Tcl_WriteRaw(out, (const char *) out_buf, (Tcl_Size) out_len);
	    if (len >= 0) {
		total += len;
	    } else {
		Tcl_AppendResult(interp, "Write error: ", Tcl_ErrnoMsg(Tcl_GetErrno()), (char *) NULL);
		res = TCL_ERROR;
		goto done;
	    }
	}
	Tcl_SetObjResult(interp, Tcl_NewIntObj(total));
    } else {
	goto done;
    }

done:
    /* Clean up */
    if (in != NULL) {
	Tcl_Close(interp, in);
    }
    if (out != NULL) {
	Tcl_Close(interp, out);
    }
    if (ctx != NULL) {
	EVP_CIPHER_CTX_free(ctx);
    }
    return res;
}

/*******************************************************************/

static const char *command_opts [] = {
    "-chan", "-channel", "-cipher", "-command", "-data", "-digest", "-infile", "-filename",
    "-outfile", "-hash", "-iv", "-key", "-mac", "-padding", NULL};

enum _command_opts {
    _opt_chan, _opt_channel, _opt_cipher, _opt_command, _opt_data, _opt_digest, _opt_infile,
    _opt_filename, _opt_outfile, _opt_hash, _opt_iv, _opt_key, _opt_mac, _opt_padding
};

/*
 *-------------------------------------------------------------------
 *
 * EncryptMain --
 *
 *	Perform encryption function and return result.
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Sets result or error message
 *
 *-------------------------------------------------------------------
 */
static int EncryptMain(int type, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Obj *cipherObj = NULL, *cmdObj = NULL, *dataObj = NULL, *digestObj = NULL;
    Tcl_Obj *inFileObj = NULL, *outFileObj = NULL, *keyObj = NULL, *ivObj = NULL, *macObj = NULL;
    const char *channel = NULL, *opt;
    int res, start = 1, padding = 1;
    Tcl_Size fn;

    dprintf("Called");

    /* Clear interp result */
    Tcl_ResetResult(interp);

    /* Validate arg count */
    if (objc < 3 || objc > 12) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-cipher? name ?-digest name? -key key ?-iv string? ?-mac name? ?-padding boolean? [-channel chan | -command cmdName | -infile filename -outfile filename | ?-data? data]");
	return TCL_ERROR;
    }

    /* Special case of first arg is cipher */
    opt = Tcl_GetString(objv[start]);
    if (opt[0] != '-') {
	switch(type) {
	case TYPE_ENCRYPT:
	case TYPE_DECRYPT:
	    cipherObj = objv[start++];
	    break;
	}
    }

    /* Get options */
    for (int idx = start; idx < objc; idx++) {
	/* Special case for when last arg is data */
	if (idx == objc - 1) {
	opt = Tcl_GetString(objv[idx]);
	    if (opt[0] != '-' && dataObj == NULL) {
		dataObj = objv[idx];
		break;
	    }
	}

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
	case _opt_chan:
	case _opt_channel:
    	    GET_OPT_STRING(objv[idx], channel, NULL);
	    break;
	case _opt_cipher:
	    cipherObj = objv[idx];
	    break;
	case _opt_command:
	    cmdObj = objv[idx];
	    break;
	case _opt_data:
	    dataObj = objv[idx];
	    break;
	case _opt_digest:
	case _opt_hash:
	    digestObj = objv[idx];
	    break;
	case _opt_infile:
	case _opt_filename:
	    inFileObj = objv[idx];
	    break;
	case _opt_outfile:
	    outFileObj = objv[idx];
	    break;
	case _opt_iv:
	    ivObj = objv[idx];
	    break;
	case _opt_key:
	    keyObj = objv[idx];
	    break;
	case _opt_mac:
	    macObj = objv[idx];
	    break;
	case _opt_padding:
    	    GET_OPT_BOOL(objv[idx], &padding);
	    break;
	}
    }

    /* Check for required options */
    if (cipherObj == NULL) {
	Tcl_AppendResult(interp, "No cipher", (char *) NULL);
    } else if (keyObj == NULL) {
	Tcl_AppendResult(interp, "No key", (char *) NULL);
	return TCL_ERROR;
    }

    /* Perform encryption function on file, stacked channel, using instance command, or data blob */
    if (inFileObj != NULL && outFileObj != NULL) {
	res = EncryptFileHandler(interp, type, inFileObj, outFileObj, cipherObj, digestObj, keyObj, ivObj, padding);
    } else if (channel != NULL) {
	res = EncryptChannelHandler(interp, type, channel, cipherObj, digestObj, keyObj, ivObj, padding);
    } else if (cmdObj != NULL) {
	res = EncryptCommandHandler(interp, type, cmdObj, cipherObj, digestObj, keyObj, ivObj, padding);
    } else if (dataObj != NULL) {
	res = EncryptDataHandler(interp, type, dataObj, cipherObj, digestObj, keyObj, ivObj, padding);
    } else {
	Tcl_AppendResult(interp, "No operation specified: Use -channel, -command, -data, or -infile option", (char *) NULL);
	res = TCL_ERROR;
    }
    return res;
}

/*
 *-------------------------------------------------------------------
 *
 * Encryption Commands --
 *
 *	Perform encryption function and return results
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Command dependent
 *
 *-------------------------------------------------------------------
 */
static int EncryptObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void) clientData;
    return EncryptMain(TYPE_ENCRYPT, interp, objc, objv);
}

static int DecryptObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void) clientData;
    return EncryptMain(TYPE_DECRYPT, interp, objc, objv);
}

/*
 *-------------------------------------------------------------------
 *
 * Encrypt_Initialize --
 *
 *	Create namespace, commands, and register package version
 *
 * Returns:
 *	TCL_OK or TCL_ERROR
 *
 * Side effects:
 *	Creates commands
 *
 *-------------------------------------------------------------------
 */
int Tls_EncryptCommands(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "::tls::encrypt", EncryptObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "::tls::decrypt", DecryptObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "::tls::unstack2", EncryptUnstackObjCmd, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    return TCL_OK;
}

