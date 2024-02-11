/*
 * Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
 * Copyright (C) 2000 Ajuba Solutions
 *
 * TLS (aka SSL) Channel - can be layered on any bi-directional
 * Tcl_Channel (Note: Requires Trf Core Patch)
 *
 * This was built from scratch based upon observation of OpenSSL 0.9.2B
 *
 * Addition credit is due for Andreas Kupries (a.kupries@westend.com), for
 * providing the Tcl_ReplaceChannel mechanism and working closely with me
 * to enhance it to support full fileevent semantics.
 *
 * Also work done by the follow people provided the impetus to do this "right":
 *    tclSSL (Colin McCormack, Shared Technology)
 *    SSLtcl (Peter Antman)
 *
 */

#include "tlsInt.h"
#include <errno.h>

/*
 * Forward declarations
 */
static void TlsChannelHandlerTimer(ClientData clientData);

/*
 *-------------------------------------------------------------------
 *
 * TlsBlockModeProc --
 *
 *    This procedure is invoked by the generic IO level
 *       to set blocking and nonblocking modes
 *
 * Results:
 *    0 if successful or POSIX error code if failed.
 *
 * Side effects:
 *    Sets the device into blocking or nonblocking mode.
 *
 *-------------------------------------------------------------------
 */
static int TlsBlockModeProc(ClientData instanceData, int mode) {
    State *statePtr = (State *) instanceData;

    if (mode == TCL_MODE_NONBLOCKING) {
	statePtr->flags |= TLS_TCL_ASYNC;
    } else {
	statePtr->flags &= ~(TLS_TCL_ASYNC);
    }
    return(0);
}

/*
 *-------------------------------------------------------------------
 *
 * TlsCloseProc --
 *
 *    This procedure is invoked by the generic IO level to perform
 *    channel-type-specific cleanup when a SSL socket based channel
 *    is closed.
 *
 *    Note: we leave the underlying socket alone, is this right?
 *
 * Results:
 *    0 if successful or POSIX error code if failed.
 *
 * Side effects:
 *    Closes the socket of the channel.
 *
 *-------------------------------------------------------------------
 */
static int TlsCloseProc(ClientData instanceData, Tcl_Interp *interp) {
    State *statePtr = (State *) instanceData;

    dprintf("TlsCloseProc(%p)", (void *) statePtr);

    Tls_Clean(statePtr);
    Tcl_EventuallyFree((ClientData)statePtr, Tls_Free);
    return(0);
}

static int TlsClose2Proc(ClientData instanceData,    /* The socket state. */
    Tcl_Interp *interp,		/* For errors - can be NULL. */
    int flags)			/* Flags to close read and/or write side of channel */
{
    State *statePtr = (State *) instanceData;

    dprintf("TlsClose2Proc(%p)", (void *) statePtr);

    if ((flags & (TCL_CLOSE_READ|TCL_CLOSE_WRITE)) == 0) {
	return TlsCloseProc(instanceData, interp);
    }
    return EINVAL;
}

/*
 *------------------------------------------------------*
 *
 * Tls_WaitForConnect --
 *
 * Result:
 *    0 if successful, -1 if failed.
 *
 * Side effects:
 *    Issues SSL_accept or SSL_connect
 *
 *------------------------------------------------------*
 */
int Tls_WaitForConnect(State *statePtr, int *errorCodePtr, int handshakeFailureIsPermanent) {
    unsigned long backingError;
    int err, rc;
    int bioShouldRetry;
    *errorCodePtr = 0;

    dprintf("WaitForConnect(%p)", (void *) statePtr);
    dprintFlags(statePtr);

    if (!(statePtr->flags & TLS_TCL_INIT)) {
	dprintf("Tls_WaitForConnect called on already initialized channel -- returning with immediate success");
	return(0);
    }

    if (statePtr->flags & TLS_TCL_HANDSHAKE_FAILED) {
	/*
	 * Different types of operations have different requirements
	 * SSL being established
	 */
	if (handshakeFailureIsPermanent) {
	    dprintf("Asked to wait for a TLS handshake that has already failed.  Returning fatal error");
	    *errorCodePtr = ECONNABORTED;
	} else {
	    dprintf("Asked to wait for a TLS handshake that has already failed.  Returning soft error");
	    *errorCodePtr = ECONNRESET;
	}
	Tls_Error(statePtr, "Wait for failed handshake");
	return(-1);
    }

    for (;;) {
	ERR_clear_error();

	/* Not initialized yet! Also calls SSL_do_handshake. */
	if (statePtr->flags & TLS_TCL_SERVER) {
	    dprintf("Calling SSL_accept()");
	    err = SSL_accept(statePtr->ssl);

	} else {
	    dprintf("Calling SSL_connect()");
	    err = SSL_connect(statePtr->ssl);
	}

	if (err > 0) {
	    dprintf("Accept or connect was successful");
	    err = BIO_flush(statePtr->bio);
	    if (err <= 0) {
		dprintf("Flushing the lower layers failed, this will probably terminate this session");
	    }
	} else {
	    dprintf("Accept or connect failed");
	}

	rc = SSL_get_error(statePtr->ssl, err);
	backingError = ERR_get_error();
	if (rc != SSL_ERROR_NONE) {
	    dprintf("Got error: %i (rc = %i)", err, rc);
	    dprintf("Got error: %s", ERR_reason_error_string(backingError));
	}

	bioShouldRetry = 0;
	if (err <= 0) {
	    if (rc == SSL_ERROR_WANT_CONNECT || rc == SSL_ERROR_WANT_ACCEPT || rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE) {
		bioShouldRetry = 1;
	    } else if (BIO_should_retry(statePtr->bio)) {
		bioShouldRetry = 1;
	    } else if (rc == SSL_ERROR_SYSCALL && Tcl_GetErrno() == EAGAIN) {
		bioShouldRetry = 1;
	    }
	} else {
	    if (!SSL_is_init_finished(statePtr->ssl)) {
		bioShouldRetry = 1;
	    }
	}

	if (bioShouldRetry) {
	    dprintf("The I/O did not complete -- but we should try it again");

	    if (statePtr->flags & TLS_TCL_ASYNC) {
		dprintf("Returning EAGAIN so that it can be retried later");
		*errorCodePtr = EAGAIN;
		Tls_Error(statePtr, "Handshake not complete, will retry later");
		return(-1);
	    } else {
		dprintf("Doing so now");
		continue;
	    }
	}

	dprintf("We have either completely established the session or completely failed it -- there is no more need to ever retry it though");
	break;
    }

    switch (rc) {
	case SSL_ERROR_NONE:
	    /* The TLS/SSL I/O operation completed */
	    dprintf("The connection is good");
	    *errorCodePtr = 0;
	    break;

	case SSL_ERROR_ZERO_RETURN:
	    /* The TLS/SSL peer has closed the connection for writing by sending the close_notify alert */
	    dprintf("SSL_ERROR_ZERO_RETURN: Connect returned an invalid value...");
	    *errorCodePtr = EINVAL;
	    Tls_Error(statePtr, "Peer has closed the connection for writing by sending the close_notify alert");
	    return(-1);

	case SSL_ERROR_SYSCALL:
	    /* Some non-recoverable, fatal I/O error occurred */
	    dprintf("SSL_ERROR_SYSCALL");
	    if (backingError == 0 && err == 0) {
		dprintf("EOF reached")
		*errorCodePtr = ECONNRESET;
		Tls_Error(statePtr, "(unexpected) EOF reached");

	    } else if (backingError == 0 && err == -1) {
		dprintf("I/O error occurred (errno = %lu)", (unsigned long) Tcl_GetErrno());
		*errorCodePtr = Tcl_GetErrno();
		if (*errorCodePtr == ECONNRESET) {
		    *errorCodePtr = ECONNABORTED;
		}
		Tls_Error(statePtr, (char *) Tcl_ErrnoMsg(*errorCodePtr));

	    } else {
		dprintf("I/O error occurred (backingError = %lu)", backingError);
		*errorCodePtr = Tcl_GetErrno();
		if (*errorCodePtr == ECONNRESET) {
		    *errorCodePtr = ECONNABORTED;
		}
		Tls_Error(statePtr, (char *) ERR_reason_error_string(backingError));
	    }

	    statePtr->flags |= TLS_TCL_HANDSHAKE_FAILED;
	    return(-1);

	case SSL_ERROR_SSL:
	    /* A non-recoverable, fatal error in the SSL library occurred, usually a protocol error */
	    dprintf("SSL_ERROR_SSL: Got permanent fatal SSL error, aborting immediately");
	    if (SSL_get_verify_result(statePtr->ssl) != X509_V_OK) {
		Tls_Error(statePtr, (char *) X509_verify_cert_error_string(SSL_get_verify_result(statePtr->ssl)));
	    }
	    if (backingError != 0) {
		Tls_Error(statePtr, (char *) ERR_reason_error_string(backingError));
	    }
	    statePtr->flags |= TLS_TCL_HANDSHAKE_FAILED;
	    *errorCodePtr = ECONNABORTED;
	    return(-1);

	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_X509_LOOKUP:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_ASYNC:
	case SSL_ERROR_WANT_ASYNC_JOB:
	case SSL_ERROR_WANT_CLIENT_HELLO_CB:
	default:
	    /* The operation did not complete and should be retried later. */
	    dprintf("Operation did not complete, call function again later: %i", rc);
	    *errorCodePtr = EAGAIN;
	    dprintf("ERR(%d, %d) ", rc, *errorCodePtr);
	    Tls_Error(statePtr, "Operation did not complete, call function again later");
	    return(-1);
    }

    dprintf("Removing the \"TLS_TCL_INIT\" flag since we have completed the handshake");
    statePtr->flags &= ~TLS_TCL_INIT;

    dprintf("Returning in success");
    *errorCodePtr = 0;
    return(0);
}

/*
 *-------------------------------------------------------------------
 *
 * TlsInputProc --
 *
 *    This procedure is invoked by the generic IO level
 *       to read input from a SSL socket based channel.
 *
 * Results:
 *    Returns the number of bytes read or -1 on error. Sets errorCodePtr
 *    to a POSIX error code if an error occurred, or 0 if none.
 *
 * Side effects:
 *    Reads input from the input device of the channel.
 *
 *-------------------------------------------------------------------
 */
static int TlsInputProc(ClientData instanceData, char *buf, int bufSize, int *errorCodePtr) {
    unsigned long backingError;
    State *statePtr = (State *) instanceData;
    int bytesRead;
    int tlsConnect;
    int err;

    *errorCodePtr = 0;

    dprintf("BIO_read(%d)", bufSize);

    if (statePtr->flags & TLS_TCL_CALLBACK) {
	/* don't process any bytes while verify callback is running */
	dprintf("Callback is running, reading 0 bytes");
	return(0);
    }

    dprintf("Calling Tls_WaitForConnect");
    tlsConnect = Tls_WaitForConnect(statePtr, errorCodePtr, 0);
    if (tlsConnect < 0) {
	dprintf("Got an error waiting to connect (tlsConnect = %i, *errorCodePtr = %i)", tlsConnect, *errorCodePtr);
	Tls_Error(statePtr, strerror(*errorCodePtr));

	bytesRead = -1;
	if (*errorCodePtr == ECONNRESET) {
	    dprintf("Got connection reset");
	    /* Soft EOF */
	    *errorCodePtr = 0;
	    bytesRead = 0;
	}
	return(bytesRead);
    }

    /*
     * We need to clear the SSL error stack now because we sometimes reach
     * this function with leftover errors in the stack.  If BIO_read
     * returns -1 and intends EAGAIN, there is a leftover error, it will be
     * misconstrued as an error, not EAGAIN.
     *
     * Alternatively, we may want to handle the <0 return codes from
     * BIO_read specially (as advised in the RSA docs).  TLS's lower level BIO
     * functions play with the retry flags though, and this seems to work
     * correctly.  Similar fix in TlsOutputProc. - hobbs
     */
    ERR_clear_error();
    bytesRead = BIO_read(statePtr->bio, buf, bufSize);
    dprintf("BIO_read -> %d", bytesRead);

    err = SSL_get_error(statePtr->ssl, bytesRead);
    backingError = ERR_get_error();

#if 0
    if (bytesRead <= 0) {
	if (BIO_should_retry(statePtr->bio)) {
	    dprintf("I/O failed, will retry based on EAGAIN");
	    *errorCodePtr = EAGAIN;
	}
    }
#endif

    switch (err) {
	case SSL_ERROR_NONE:
	    dprintBuffer(buf, bytesRead);
	    break;

	case SSL_ERROR_SSL:
	    /* A non-recoverable, fatal error in the SSL library occurred, usually a protocol error */
	    dprintf("SSL error, indicating that the connection has been aborted");
	    if (backingError != 0) {
		Tls_Error(statePtr, (char *) ERR_reason_error_string(backingError));
	    } else if (SSL_get_verify_result(statePtr->ssl) != X509_V_OK) {
		Tls_Error(statePtr, (char *) X509_verify_cert_error_string(SSL_get_verify_result(statePtr->ssl)));
	    } else {
		Tls_Error(statePtr, "Unknown SSL error");
	    }
	    *errorCodePtr = ECONNABORTED;
	    bytesRead = -1;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	    /* Unexpected EOF from the peer for OpenSSL 3.0+ */
	    if (ERR_GET_REASON(backingError) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
		dprintf("(Unexpected) EOF reached")
		*errorCodePtr = 0;
		bytesRead = 0;
		Tls_Error(statePtr, "EOF reached");
	    }    
#endif
	    break;

	case SSL_ERROR_SYSCALL:
	    /* Some non-recoverable, fatal I/O error occurred */
	    if (backingError == 0 && bytesRead == 0) {
		/* Unexpected EOF from the peer for OpenSSL 1.1 */
		dprintf("(Unexpected) EOF reached")
		*errorCodePtr = 0;
		bytesRead = 0;
		Tls_Error(statePtr, "EOF reached");

	    } else if (backingError == 0 && bytesRead == -1) {
		dprintf("I/O error occurred (errno = %lu)", (unsigned long) Tcl_GetErrno());
		*errorCodePtr = Tcl_GetErrno();
		bytesRead = -1;
		Tls_Error(statePtr, (char *) Tcl_ErrnoMsg(*errorCodePtr));

	    } else {
		dprintf("I/O error occurred (backingError = %lu)", backingError);
		*errorCodePtr = Tcl_GetErrno();
		bytesRead = -1;
		Tls_Error(statePtr, (char *) ERR_reason_error_string(backingError));
	    }
	    break;

	case SSL_ERROR_ZERO_RETURN:
	    dprintf("Got SSL_ERROR_ZERO_RETURN, this means an EOF has been reached");
	    bytesRead = 0;
	    *errorCodePtr = 0;
	    Tls_Error(statePtr, "Peer has closed the connection for writing by sending the close_notify alert");
	    break;

	case SSL_ERROR_WANT_READ:
	    dprintf("Got SSL_ERROR_WANT_READ, mapping this to EAGAIN");
	    bytesRead = -1;
	    *errorCodePtr = EAGAIN;
	    Tls_Error(statePtr, "SSL_ERROR_WANT_READ");
	    break;

	default:
	    dprintf("Unknown error (err = %i), mapping to EOF", err);
	    *errorCodePtr = 0;
	    bytesRead = 0;
	    Tls_Error(statePtr, "Unknown error");
	    break;
    }

    dprintf("Input(%d) -> %d [%d]", bufSize, bytesRead, *errorCodePtr);
    return(bytesRead);
}

/*
 *-------------------------------------------------------------------
 *
 * TlsOutputProc --
 *
 *    This procedure is invoked by the generic IO level
 *       to write output to a SSL socket based channel.
 *
 * Results:
 *    Returns the number of bytes written or -1 on error. Sets errorCodePtr
 *    to a POSIX error code if an error occurred, or 0 if none.
 *
 * Side effects:
 *    Writes output on the output device of the channel.
 *
 *-------------------------------------------------------------------
 */
static int TlsOutputProc(ClientData instanceData, const char *buf, int toWrite, int *errorCodePtr) {
    unsigned long backingError;
    State *statePtr = (State *) instanceData;
    int written, err;
    int tlsConnect;

    *errorCodePtr = 0;

    dprintf("BIO_write(%p, %d)", (void *) statePtr, toWrite);
    dprintBuffer(buf, toWrite);

    if (statePtr->flags & TLS_TCL_CALLBACK) {
	dprintf("Don't process output while callbacks are running");
	written = -1;
	*errorCodePtr = EAGAIN;
	return(-1);
    }

    dprintf("Calling Tls_WaitForConnect");
    tlsConnect = Tls_WaitForConnect(statePtr, errorCodePtr, 1);
    if (tlsConnect < 0) {
	dprintf("Got an error waiting to connect (tlsConnect = %i, *errorCodePtr = %i)", tlsConnect, *errorCodePtr);
	Tls_Error(statePtr, strerror(*errorCodePtr));

	written = -1;
	if (*errorCodePtr == ECONNRESET) {
	    dprintf("Got connection reset");
	    /* Soft EOF */
	    *errorCodePtr = 0;
	    written = 0;
	}
	return(written);
    }

    if (toWrite == 0) {
	dprintf("zero-write");
	err = BIO_flush(statePtr->bio);

	if (err <= 0) {
	    dprintf("Flushing failed");
	    Tls_Error(statePtr, "Flush failed");

	    *errorCodePtr = EIO;
	    written = 0;
	    return(-1);
	}

	written = 0;
	*errorCodePtr = 0;
	return(0);
    }

    /*
     * We need to clear the SSL error stack now because we sometimes reach
     * this function with leftover errors in the stack.  If BIO_write
     * returns -1 and intends EAGAIN, there is a leftover error, it will be
     * misconstrued as an error, not EAGAIN.
     *
     * Alternatively, we may want to handle the <0 return codes from
     * BIO_write specially (as advised in the RSA docs).  TLS's lower level
     * BIO functions play with the retry flags though, and this seems to
     * work correctly.  Similar fix in TlsInputProc. - hobbs
     */
    ERR_clear_error();
    written = BIO_write(statePtr->bio, buf, toWrite);
    dprintf("BIO_write(%p, %d) -> [%d]", (void *) statePtr, toWrite, written);

    err = SSL_get_error(statePtr->ssl, written);
    backingError = ERR_get_error();

    switch (err) {
	case SSL_ERROR_NONE:
	    if (written < 0) {
		written = 0;
	    }
	    break;

	case SSL_ERROR_WANT_WRITE:
	    dprintf("Got SSL_ERROR_WANT_WRITE, mapping it to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    written = -1;
	    Tls_Error(statePtr, "SSL_ERROR_WANT_WRITE");
	    break;

	case SSL_ERROR_WANT_READ:
	    dprintf(" write R BLOCK");
	    Tls_Error(statePtr, "SSL_ERROR_WANT_READ");
	    break;

	case SSL_ERROR_WANT_X509_LOOKUP:
	    dprintf(" write X BLOCK");
	    Tls_Error(statePtr, "SSL_ERROR_WANT_X509_LOOKUP");
	    break;

	case SSL_ERROR_ZERO_RETURN:
	    dprintf(" closed");
	    written = 0;
	    *errorCodePtr = 0;
	    Tls_Error(statePtr, "Peer has closed the connection for writing by sending the close_notify alert");
	    break;

	case SSL_ERROR_SYSCALL:
	    /* Some non-recoverable, fatal I/O error occurred */
	    if (backingError == 0 && written == 0) {
		dprintf("EOF reached")
		*errorCodePtr = 0;
		written = 0;
		Tls_Error(statePtr, "EOF reached");

	    } else if (backingError == 0 && written == -1) {
		dprintf("I/O error occurred (errno = %lu)", (unsigned long) Tcl_GetErrno());
		*errorCodePtr = Tcl_GetErrno();
		written = -1;
		Tls_Error(statePtr, (char *) Tcl_ErrnoMsg(*errorCodePtr));

	    } else {
		dprintf("I/O error occurred (backingError = %lu)", backingError);
		*errorCodePtr = Tcl_GetErrno();
		written = -1;
		Tls_Error(statePtr, (char *) ERR_reason_error_string(backingError));
	    }
	    break;

	case SSL_ERROR_SSL:
	    /* A non-recoverable, fatal error in the SSL library occurred, usually a protocol error */
	    dprintf("SSL error, indicating that the connection has been aborted");
	    if (backingError != 0) {
		Tls_Error(statePtr, (char *) ERR_reason_error_string(backingError));
	    } else if (SSL_get_verify_result(statePtr->ssl) != X509_V_OK) {
		Tls_Error(statePtr, (char *) X509_verify_cert_error_string(SSL_get_verify_result(statePtr->ssl)));
	    } else {
		Tls_Error(statePtr, "Unknown SSL error");
	    }
	    *errorCodePtr = ECONNABORTED;
	    written = -1;
	    break;

	default:
	    dprintf("unknown error: %d", err);
	    Tls_Error(statePtr, "Unknown error");
	    break;
    }

    dprintf("Output(%d) -> %d", toWrite, written);
    return(written);
}

/*
 *-------------------------------------------------------------------
 *
 * TlsSetOptionProc --
 *
 *    Sets an option value for a SSL socket based channel, or a
 *    list of all options and their values.
 *
 * Results:
 *    TCL_OK if successful or TCL_ERROR if failed.
 *
 * Side effects:
 *    Updates channel option to new value.
 *
 *-------------------------------------------------------------------
 */
static int
TlsSetOptionProc(ClientData instanceData,    /* Socket state. */
    Tcl_Interp *interp,		/* For errors - can be NULL. */
    const char *optionName,	/* Name of the option to set the value for, or
				 * NULL to get all options and their values. */
    const char *optionValue)	/* Value for option. */
{
    State *statePtr = (State *) instanceData;

    Tcl_Channel downChan = Tls_GetParent(statePtr, TLS_TCL_FASTPATH);
    Tcl_DriverSetOptionProc *setOptionProc;

    setOptionProc = Tcl_ChannelSetOptionProc(Tcl_GetChannelType(downChan));
    if (setOptionProc != NULL) {
	return (*setOptionProc)(Tcl_GetChannelInstanceData(downChan), interp, optionName, optionValue);
    } else if (optionName == (char*) NULL) {
	/*
	 * Request is query for all options, this is ok.
	 */
	return TCL_OK;
    }
    /*
     * Request for a specific option has to fail, we don't have any.
     */
    return Tcl_BadChannelOption(interp, optionName, "");
}

/*
 *-------------------------------------------------------------------
 *
 * TlsGetOptionProc --
 *
 *    Gets an option value for a SSL socket based channel, or a
 *    list of all options and their values.
 *
 * Results:
 *    A standard Tcl result. The value of the specified option or a
 *    list of all options and their values is returned in the
 *    supplied DString.
 *
 * Side effects:
 *    None.
 *
 *-------------------------------------------------------------------
 */
static int
TlsGetOptionProc(ClientData instanceData,    /* Socket state. */
    Tcl_Interp *interp,		/* For errors - can be NULL. */
    const char *optionName,	/* Name of the option to retrieve the value for, or
				 * NULL to get all options and their values. */
    Tcl_DString *optionValue)	/* Where to store the computed value initialized by caller. */
{
    State *statePtr = (State *) instanceData;

    Tcl_Channel downChan = Tls_GetParent(statePtr, TLS_TCL_FASTPATH);
    Tcl_DriverGetOptionProc *getOptionProc;

    getOptionProc = Tcl_ChannelGetOptionProc(Tcl_GetChannelType(downChan));
    if (getOptionProc != NULL) {
	return (*getOptionProc)(Tcl_GetChannelInstanceData(downChan), interp, optionName, optionValue);
    } else if (optionName == (char*) NULL) {
	/*
	 * Request is query for all options, this is ok.
	 */
	return TCL_OK;
    }
    /*
     * Request for a specific option has to fail, we don't have any.
     */
    return Tcl_BadChannelOption(interp, optionName, "");
}

/*
 *-------------------------------------------------------------------
 *
 * TlsWatchProc --
 *
 *    Initialize the notifier to watch Tcl_Files from this channel.
 *
 * Results:
 *    None.
 *
 * Side effects:
 *    Sets up the notifier so that a future event on the channel
 *    will be seen by Tcl.
 *
 *-------------------------------------------------------------------
 */
static void
TlsWatchProc(ClientData instanceData,    /* The socket state. */
    int mask)			/* Events of interest; an OR-ed combination of
				 * TCL_READABLE, TCL_WRITABLE and TCL_EXCEPTION. */
{
    Tcl_Channel     downChan;
    State *statePtr = (State *) instanceData;
    Tcl_DriverWatchProc *watchProc;

    dprintf("TlsWatchProc(0x%x)", mask);

    /* Pretend to be dead as long as the verify callback is running.
     * Otherwise that callback could be invoked recursively. */
    if (statePtr->flags & TLS_TCL_CALLBACK) {
	dprintf("Callback is on-going, doing nothing");
	return;
    }

    dprintFlags(statePtr);

    downChan = Tls_GetParent(statePtr, TLS_TCL_FASTPATH);

    if (statePtr->flags & TLS_TCL_HANDSHAKE_FAILED) {
	dprintf("Asked to watch a socket with a failed handshake -- nothing can happen here");
	dprintf("Unregistering interest in the lower channel");

	watchProc = Tcl_ChannelWatchProc(Tcl_GetChannelType(downChan));
	watchProc(Tcl_GetChannelInstanceData(downChan), 0);
	statePtr->watchMask = 0;
	return;
    }

    statePtr->watchMask = mask;

    /* No channel handlers any more. We will be notified automatically
     * about events on the channel below via a call to our
     * 'TransformNotifyProc'. But we have to pass the interest down now.
     * We are allowed to add additional 'interest' to the mask if we want
     * to. But this transformation has no such interest. It just passes
     * the request down, unchanged.
     */
    dprintf("Registering our interest in the lower channel (chan=%p)", (void *) downChan);
    watchProc = Tcl_ChannelWatchProc(Tcl_GetChannelType(downChan));
    watchProc(Tcl_GetChannelInstanceData(downChan), mask);


    /*
     * Management of the internal timer.
     */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	dprintf("A timer was found, deleting it");
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
    }

    if ((mask & TCL_READABLE) &&
	((Tcl_InputBuffered(statePtr->self) > 0) || (BIO_ctrl_pending(statePtr->bio) > 0))) {
	/*
	 * There is interest in readable events and we actually have
	 * data waiting, so generate a timer to flush that.
	 */
	dprintf("Creating a new timer since data appears to be waiting");
	statePtr->timer = Tcl_CreateTimerHandler(TLS_TCL_DELAY, TlsChannelHandlerTimer, (ClientData) statePtr);
    }
}

/*
 *-------------------------------------------------------------------
 *
 * TlsGetHandleProc --
 *
 *    Called from Tcl_GetChannelFile to retrieve o/s file handler
 *    from the SSL socket based channel.
 *
 * Results:
 *    The appropriate Tcl_File handle or NULL if none.
 *
 * Side effects:
 *    None.
 *
 *-------------------------------------------------------------------
 */
static int TlsGetHandleProc(ClientData instanceData,    /* Socket state. */
    int direction,		/* TCL_READABLE or TCL_WRITABLE */
    ClientData *handlePtr)	/* Handle associated with the channel */
{
    State *statePtr = (State *) instanceData;

    return(Tcl_GetChannelHandle(Tls_GetParent(statePtr, TLS_TCL_FASTPATH), direction, handlePtr));
}

/*
 *-------------------------------------------------------------------
 *
 * TlsNotifyProc --
 *
 *    Handler called by Tcl to inform us of activity
 *    on the underlying channel.
 *
 * Results:
 *    Type of event or 0 if failed
 *
 * Side effects:
 *    May process the incoming event by itself.
 *
 *-------------------------------------------------------------------
 */
static int TlsNotifyProc(ClientData instanceData,    /* Socket state. */
    int mask)			/* type of event that occurred:
				 * OR-ed combination of TCL_READABLE or TCL_WRITABLE */
{
    State *statePtr = (State *) instanceData;
    int errorCode;

    /*
     * An event occurred in the underlying channel.  This
     * transformation doesn't process such events thus returns the
     * incoming mask unchanged.
     */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	/*
	 * Delete an existing timer. It was not fired, yet we are
	 * here, so the channel below generated such an event and we
	 * don't have to. The renewal of the interest after the
	 * execution of channel handlers will eventually cause us to
	 * recreate the timer (in WatchProc).
	 */
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
    }

    if (statePtr->flags & TLS_TCL_CALLBACK) {
	dprintf("Returning 0 due to callback");
	return 0;
    }

    dprintf("Calling Tls_WaitForConnect");
    errorCode = 0;
    if (Tls_WaitForConnect(statePtr, &errorCode, 1) < 0) {
	Tls_Error(statePtr, strerror(errorCode));
	if (errorCode == EAGAIN) {
	    dprintf("Async flag could be set (didn't check) and errorCode == EAGAIN:  Returning 0");

	    return 0;
	}

	dprintf("Tls_WaitForConnect returned an error");
    }

    dprintf("Returning %i", mask);

    return(mask);
}

/*
 *------------------------------------------------------*
 *
 *    TlsChannelHandlerTimer --
 *
 *    ------------------------------------------------*
 *    Called by the notifier (-> timer) to flush out
 *    information waiting in channel buffers.
 *    ------------------------------------------------*
 *
 *    Side effects:
 *        As of 'TlsChannelHandler'.
 *
 *    Result:
 *        None.
 *
 *------------------------------------------------------*
 */
static void TlsChannelHandlerTimer(ClientData clientData) {
    State *statePtr = (State *) clientData;
    int mask = 0;

    dprintf("Called");

    statePtr->timer = (Tcl_TimerToken) NULL;

    if (BIO_wpending(statePtr->bio)) {
	dprintf("[chan=%p] BIO writable", statePtr->self);

	mask |= TCL_WRITABLE;
    }

    if (BIO_pending(statePtr->bio)) {
	dprintf("[chan=%p] BIO readable", statePtr->self);

	mask |= TCL_READABLE;
    }

    dprintf("Notifying ourselves");
    Tcl_NotifyChannel(statePtr->self, mask);

    dprintf("Returning");

    return;
}

Tcl_Channel Tls_GetParent(State *statePtr, int maskFlags) {
    dprintf("Requested to get parent of channel %p", statePtr->self);

    if ((statePtr->flags & ~maskFlags) & TLS_TCL_FASTPATH) {
	dprintf("Asked to get the parent channel while we are using FastPath -- returning NULL");
	return(NULL);
    }
    return(Tcl_GetStackedChannel(statePtr->self));
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_ChannelType --
 *
 *    Return the correct TLS channel driver info
 *
 * Results:
 *    The correct channel driver for the current version of Tcl.
 *
 * Side effects:
 *    None.
 *
 *-------------------------------------------------------------------
 */
static const Tcl_ChannelType tlsChannelType = {
    "tls",			/* Type name */
    TCL_CHANNEL_VERSION_5,	/* v5 channel */
    TlsCloseProc,		/* Close proc */
    TlsInputProc,		/* Input proc */
    TlsOutputProc,		/* Output proc */
    NULL,			/* Seek proc */
    TlsSetOptionProc,		/* Set option proc */
    TlsGetOptionProc,		/* Get option proc */
    TlsWatchProc,		/* Initialize notifier */
    TlsGetHandleProc,		/* Get OS handles out of channel */
    TlsClose2Proc,		/* close2proc */
    TlsBlockModeProc,		/* Set blocking/nonblocking mode*/
    NULL,			/* Flush proc */
    TlsNotifyProc,		/* Handling of events bubbling up */
    NULL,			/* Wide seek proc */
    NULL,			/* Thread action */
    NULL			/* Truncate */
};

const Tcl_ChannelType *Tls_ChannelType(void) {
    return &tlsChannelType;
}
