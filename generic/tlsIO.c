/*
 * Provides IO functions to interface between the BIO buffers and TCL
 * applications when using stacked channels.
 *
 * Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
 * Copyright (C) 2000 Ajuba Solutions
 * Copyright (C) 2024-2025 Brian O'Hagan
 *
 * Additional credit is due for Andreas Kupries (a.kupries@westend.com), for
 * providing the Tcl_ReplaceChannel mechanism and working closely with me
 * to enhance it to support full fileevent semantics.
 *
 * Also work done by the follow people provided the impetus to do this "right":
 *	tclSSL (Colin McCormack, Shared Technology)
 *	SSLtcl (Peter Antman)
 *
 */

/*
Normal
		tlsBIO.c			tlsIO.c
 +------+                        +-----+                                 +---+
 |      |Tcl_WriteRaw<--BioOutput| SSL |BIO_write<--TlsOutputProc <--puts|   |
 |socket|      <encrypted>       | BIO |            <unencrypted>        |App|
 |      |Tcl_ReadRaw --> BioInput|     |BIO_Read -->TlsInputProc --> read|   |
 +------+                        +-----+                                 +---+


Fast Path
						tlsIO.c
  +------+             +-----+                                    +-----+
  |      |<-- write <--| SSL |BIO_write <-- TlsOutputProc <-- puts|     |
  |socket| <encrypted> | BIO |            <unencrypted>           | App |
  |      |-->  read -->|     |BIO_Read  --> TlsInputProc -->  read|     |
  +------+             +-----+                                    +-----+
*/

#include "tlsInt.h"
#include <errno.h>

/*
 *-----------------------------------------------------------------------------
 *
 * TlsBlockModeProc --
 *
 *	This procedure is invoked by the generic IO level to set the channel to
 *	blocking or nonblocking mode. Called by the generic I/O layer whenever
 *	the Tcl_SetChannelOption() function is used with option -blocking. Each
 *	stacked channel is configured individually.
 *
 * Results:
 *	0 if successful or POSIX error code if failed.
 *
 * Side effects:
 *	Sets the device into blocking or nonblocking mode.
 *
 *-----------------------------------------------------------------------------
 */
static int TlsBlockModeProc(
    ClientData instanceData,	/* Connection state info */
    int mode)			/* Blocking or non-blocking mode */
{
    State *statePtr = (State *) instanceData;

    dprintf("Called with mode %d", mode);

    if (mode == TCL_MODE_NONBLOCKING) {
	statePtr->flags |= TLS_TCL_ASYNC;
    } else {
	statePtr->flags &= ~(TLS_TCL_ASYNC);
    }
    return 0;
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsCloseProc --
 *
 *	This procedure is invoked by the generic IO level to perform channel
 *	type specific cleanup when a SSL socket based channel is closed. Called
 *	by the generic I/O layer whenever the Tcl_Close() function is used.
 *
 * Results:
 *	0 if successful or POSIX error code if failed.
 *
 * Side effects:
 *	Closes the socket for the channel.
 *
 *-----------------------------------------------------------------------------
 */
static int TlsCloseProc(
    ClientData instanceData,	/* Connection state info */
    Tcl_Interp *interp)		/* Tcl interpreter to report errors to */
{
    State *statePtr = (State *) instanceData;

    dprintf("Close(%p)", (void *) statePtr);

    /* Send shutdown notification. Will return 0 while in process, then 1 when
       complete. Only closes the write direction of the connection; the read
       direction is closed by the peer. Does not affect socket state. Don't
       call after fatal error. */
    if (statePtr->ssl != NULL && !(statePtr->flags & TLS_TCL_HANDSHAKE_FAILED)) {
	BIO_flush(statePtr->bio);
	SSL_shutdown(statePtr->ssl);
    }

    /* Tls_Free calls Tls_Clean */
    Tcl_EventuallyFree((ClientData)statePtr, Tls_Free);
    return 0;
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsClose2Proc --
 *
 *	Similar to TlsCloseProc, but allows for separate close of the read or
 *	write side of the channel. We don't support these since TLS is a
 *	bi-directional protocol.
 *
 * Results:
 *	0 if successful or POSIX error code if failed.
 *
 * Side effects:
 *	Closes the socket for the channel.
 *
 *-----------------------------------------------------------------------------
 */
static int TlsClose2Proc(
    ClientData instanceData,	/* Connection state info */
    Tcl_Interp *interp,		/* Tcl interpreter to report errors to */
    int flags)			/* Flags to close read/write side of channel */
{
    State *statePtr = (State *) instanceData;

    dprintf("Called with flags %d", flags);

    if ((flags & (TCL_CLOSE_READ|TCL_CLOSE_WRITE)) == 0) {
	return TlsCloseProc(instanceData, interp);
    }
    return EINVAL;
}

/*
 *-----------------------------------------------------------------------------
 *
 * Tls_WaitForConnect --
 *
 *	Perform connect (client) or accept (server) function. Also performs
 *	equivalent of handshake function.
 *
 * Result:
 *	1 if successful, 0 if waiting for connect, and -1 if failed. Sets
 *	errorCodePtr to a POSIX error code if an error occurred, or 0 if not.
 *
 * Side effects:
 *	Performs SSL_accept or SSL_connect.
 *
 *-----------------------------------------------------------------------------
 */
int Tls_WaitForConnect(
    State *statePtr,			/* Connection state info */
    int *errorCodePtr,			/* Storage for error code to return */
    int handshakeFailureIsPermanent)	/* Is the connect failure permanent */
{
    unsigned long backingError;
    int err, rc;
    *errorCodePtr = 0;

    dprintf("WaitForConnect(%p)", (void *) statePtr);
    dprintf("Called with handshakeFailureIsPermanent %d", handshakeFailureIsPermanent);
    dprintFlags(statePtr);

    /* Can also check SSL_is_init_finished(ssl) */
    if (!(statePtr->flags & TLS_TCL_INIT)) {
	dprintf("Tls_WaitForConnect called on already initialized channel -- returning with immediate success");
	return 1;
    }

    /* Different types of operations have different requirements for SSL being established. */
    if (statePtr->flags & TLS_TCL_HANDSHAKE_FAILED) {
	if (handshakeFailureIsPermanent) {
	    dprintf("Asked to wait for a TLS handshake that has already failed.  Returning fatal error");
	    *errorCodePtr = ECONNABORTED;
	} else {
	    dprintf("Asked to wait for a TLS handshake that has already failed.  Returning soft error");
	    *errorCodePtr = ECONNRESET;
	}
	return -1;
    }

    /*
     * We need to clear the SSL error stack now because we sometimes reach
     * this function with leftover errors in the stack.  If accept or connect
     * return -1 and intends EAGAIN, there is a leftover error, it will be
     * misconstrued as an error, not EAGAIN.
     */
    ERR_clear_error();
    BIO_clear_retry_flags(statePtr->bio);

    /* Not initialized yet! Also calls SSL_do_handshake(). */
    if (statePtr->flags & TLS_TCL_SERVER) {
	dprintf("Calling SSL_accept()");
	rc = SSL_accept(statePtr->ssl);

    } else {
	dprintf("Calling SSL_connect()");
	rc = SSL_connect(statePtr->ssl);
    }
    err = SSL_get_error(statePtr->ssl, rc);
    backingError = ERR_get_error();

    if (rc <= 0) {
	dprintf("Accept/connect failed: is EOF=%d, should retry=%d, retry read=%d, retry write=%d, other=%d",
	    BIO_eof(statePtr->bio),
	    BIO_should_retry(statePtr->bio), BIO_should_read(statePtr->bio),
	    BIO_should_write(statePtr->bio), BIO_should_io_special(statePtr->bio));
    }

    /* Based on error, do retry or abort */
    switch (err) {
	case SSL_ERROR_NONE:
	    /* The TLS/SSL I/O operation completed successfully */
	    dprintf("SSL_ERROR_NONE");
	    *errorCodePtr = 0;
	    break;

	case SSL_ERROR_SSL:
	    /* A non-recoverable, fatal error in the SSL library occurred,
	       usually a protocol error. This includes certificate validation
	       errors. */
	    dprintf("SSL_ERROR_SSL: Fatal SSL protocol error occurred");
	    if (SSL_get_verify_result(statePtr->ssl) != X509_V_OK) {
		Tls_Error(statePtr,
		    X509_verify_cert_error_string(SSL_get_verify_result(statePtr->ssl)));
	    }
	    if (backingError != 0) {
		Tls_Error(statePtr, ERR_reason_error_string(backingError));
	    }
	    statePtr->flags |= TLS_TCL_HANDSHAKE_FAILED;
	    statePtr->flags |= TLS_TCL_EOF;
	    *errorCodePtr = ECONNABORTED;
	    return -1;

	case SSL_ERROR_WANT_READ:
	    /* More data must be read from the underlying BIO layer in order to
	       complete the actual SSL_*() operation.  */
	    dprintf("SSL_ERROR_WANT_READ: EAGAIN");
	    BIO_set_retry_read(statePtr->bio);
	    *errorCodePtr = EAGAIN;
	    statePtr->want |= TCL_READABLE;
	    return 0;

	case SSL_ERROR_WANT_WRITE:
	    /* There is data in the SSL buffer that must be written to the
	       underlying BIO in order to complete the SSL_*() operation. */
	    dprintf("SSL_ERROR_WANT_WRITE: EAGAIN");
	    BIO_set_retry_write(statePtr->bio);
	    *errorCodePtr = EAGAIN;
	    statePtr->want |= TCL_WRITABLE;
	    return 0;

	case SSL_ERROR_WANT_X509_LOOKUP:
	    /* The operation did not complete because an application callback
	       set by SSL_CTX_set_client_cert_cb() has asked to be called again. */
	    dprintf("SSL_ERROR_WANT_X509_LOOKUP: EAGAIN");
	    BIO_set_retry_special(statePtr->bio);
	    BIO_set_retry_reason(statePtr->bio, BIO_RR_SSL_X509_LOOKUP);
	    *errorCodePtr = EAGAIN;
	    return 0;

	case SSL_ERROR_SYSCALL:
	    /* Some non-recoverable, fatal I/O error occurred */
	    dprintf("SSL_ERROR_SYSCALL: Fatal I/O error occurred");

	    if (backingError == 0 && rc == 0) {
		dprintf("EOF reached")
		*errorCodePtr = ECONNRESET;
		Tls_Error(statePtr, "(unexpected) EOF reached");

	    } else if (backingError == 0 && rc == -1) {
		dprintf("I/O error occurred (errno = %lu)", (unsigned long) Tcl_GetErrno());
		*errorCodePtr = Tcl_GetErrno();
		if (*errorCodePtr == ECONNRESET) {
		    *errorCodePtr = ECONNABORTED;
		}
		Tls_Error(statePtr, Tcl_ErrnoMsg(*errorCodePtr));

	    } else {
		dprintf("I/O error occurred (backingError = %lu)", backingError);
		*errorCodePtr = Tcl_GetErrno();
		if (*errorCodePtr == ECONNRESET) {
		    *errorCodePtr = ECONNABORTED;
		}
		Tls_Error(statePtr, ERR_reason_error_string(backingError));
	    }

	    statePtr->flags |= TLS_TCL_HANDSHAKE_FAILED;
	    statePtr->flags |= TLS_TCL_EOF;
	    return -1;

	case SSL_ERROR_ZERO_RETURN:
	    /* Peer has cleanly closed the connection by sending the close_notify
	       alert. Can't read, but can write. Need to return an EOF, so the
	       channel is closed which will send an SSL_shutdown(). */
	    dprintf("SSL_ERROR_ZERO_RETURN: Peer has closed the connection");
	    *errorCodePtr = ECONNRESET;
	    statePtr->flags |= TLS_TCL_EOF;
	    Tls_Error(statePtr, "Peer has closed the connection for writing by sending the close_notify alert");
	    return -1;

	case SSL_ERROR_WANT_CONNECT:
	    /* The operation did not complete and connect would have blocked.
	       Retry again after connection is established. */
	    dprintf("SSL_ERROR_WANT_CONNECT: EAGAIN");
	    BIO_set_retry_special(statePtr->bio);
	    BIO_set_retry_reason(statePtr->bio, BIO_RR_CONNECT);
	    *errorCodePtr = EAGAIN;
	    return 0;

	case SSL_ERROR_WANT_ACCEPT:
	    /* The operation did not complete and accept would have blocked.
	       Retry again after connection is established. */
	    dprintf("SSL_ERROR_WANT_ACCEPT: EAGAIN");
	    BIO_set_retry_special(statePtr->bio);
	    BIO_set_retry_reason(statePtr->bio, BIO_RR_ACCEPT);
	    *errorCodePtr = EAGAIN;
	    return 0;

	case SSL_ERROR_WANT_ASYNC:
	    /* Used with flag SSL_MODE_ASYNC, op didn't complete because an
	       async engine is still processing data */
	case SSL_ERROR_WANT_ASYNC_JOB:
	    /* The asynchronous job could not be started because there were no
	       async jobs available in the pool. */
	case SSL_ERROR_WANT_CLIENT_HELLO_CB:
	    /* The operation did not complete because an application callback
	       set by SSL_CTX_set_client_hello_cb() has asked to be called again. */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	case SSL_ERROR_WANT_RETRY_VERIFY:
	    /* The operation did not complete because a certificate verification
	       callback has asked to be called again via SSL_set_retry_verify(3). */
#endif
	default:
	    /* The operation did not complete and should be retried later. */
	    dprintf("Operation did not complete, call function again later");
	    *errorCodePtr = EAGAIN;
	    dprintf("ERR(Other, EAGAIN)");
	    return 0;
    }

    dprintf("Removing the \"TLS_TCL_INIT\" flag since we have completed the handshake");
    statePtr->flags &= ~TLS_TCL_INIT;

    dprintf("Returning success");
    *errorCodePtr = 0;
    return 1;
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsInputProc --
 *
 *	This procedure is invoked by the generic I/O layer to read data from
 *	the BIO whenever the Tcl_Read, Tcl_ReadChars, Tcl_Gets, and Tcl_GetsObj
 *	functions are used. Equivalent to SSL_read_ex and SSL_read.
 *
 * Results:
 *	Returns the number of bytes read or -1 on error. Sets errorCodePtr to
 *	a POSIX error code if an error occurred, or 0 if successful.
 *
 * Side effects:
 *	Reads data from SSL/BIO.
 *
 * Notes:
 *	Data is received in whole blocks known as records from the peer. A 
 *	whole record is processed (e.g. decrypted) in one go and is buffered by
 *	OpenSSL until it is read by the application via a call to SSL_read() or
 *	BIO_read() in our case. SSL_pending() returns the number of bytes which
 *	have been processed, buffered, and are available inside ssl for
 *	immediate read. SSL_has_pending() returns 1 if data is buffered
 *	(whether processed or unprocessed) and 0 otherwise.
 *
 *-----------------------------------------------------------------------------
 */
static int TlsInputProc(
    ClientData instanceData,	/* Connection state info */
    char *buf,			/* Buffer to store data read from BIO */
    int bufSize,		/* Buffer size in bytes */
    int *errorCodePtr)		/* Storage for error code to return */
{
    unsigned long backingError;
    State *statePtr = (State *) instanceData;
    int bytesRead, err;
    *errorCodePtr = 0;

    dprintf("Read %d bytes", bufSize);

    /* Abort if the user verify callback is still running to avoid triggering
     * another call before the current one is complete. */
    if (statePtr->flags & TLS_TCL_CALLBACK) {
	dprintf("Callback is running, reading 0 bytes");
	return 0;
    }

    /* Abort if EOF already detected. Can't read, but can write. */
    if (statePtr->flags & TLS_TCL_EOF) {
	dprintf("EOF already detected, abort read");
	return 0;
    }

    /* If not initialized, do connect */
    /* Can also check SSL_is_init_finished(ssl) */
    if (statePtr->flags & TLS_TCL_INIT) {
	int tlsConnect;

	dprintf("Calling Tls_WaitForConnect");

	tlsConnect = Tls_WaitForConnect(statePtr, errorCodePtr, 0);
	if (tlsConnect < 0) {
	    /* Failure, so abort */
	    dprintf("Got an error waiting to connect (tlsConnect = %i, *errorCodePtr = %i)", tlsConnect, *errorCodePtr);

	    bytesRead = -1;
	    if (*errorCodePtr == ECONNRESET) {
		dprintf("Got connection reset");
		/* Soft EOF */
		*errorCodePtr = 0;
		bytesRead = 0;
		statePtr->flags |= TLS_TCL_EOF;
	    }
	    return bytesRead;
	} else if (tlsConnect == 0) {
	    /* Try again */
	    bytesRead = -1;
	    return bytesRead;
	}
    }

    /*
     * We need to clear the SSL error stack now because we sometimes reach
     * this function with leftover errors in the stack.  If BIO_read
     * returns -1 and intends EAGAIN, there is a leftover error, it will be
     * misconstrued as an error, not EAGAIN.
     */
    dprintf("BIO_read: Chan pending=%d, SSL pending=%d", BIO_pending(statePtr->bio), SSL_pending(statePtr->ssl));
    ERR_clear_error();
    BIO_clear_retry_flags(statePtr->bio);
    bytesRead = BIO_read(statePtr->bio, buf, bufSize);
    dprintf("BIO_read -> %d", bytesRead);

    /* Same as SSL_want, but also checks the error queue */
    err = SSL_get_error(statePtr->ssl, bytesRead);
    backingError = ERR_get_error();

    if (bytesRead <= 0) {
	dprintf("Read failed: is EOF=%d, should retry=%d, retry read=%d, retry write=%d, other=%d",
	    BIO_eof(statePtr->bio),
	    BIO_should_retry(statePtr->bio), BIO_should_read(statePtr->bio),
	    BIO_should_write(statePtr->bio), BIO_should_io_special(statePtr->bio));
    }

    /* Based on error, do retry or abort */
    switch (err) {
	case SSL_ERROR_NONE:
	    /* I/O operation completed */
	    dprintf("SSL_ERROR_NONE");
	    dprintBuffer(buf, bytesRead);
	    break;

	case SSL_ERROR_SSL:
	    /* A non-recoverable, fatal error in the SSL library occurred,
	       usually a protocol error. */
	    dprintf("SSL_ERROR_SSL: Fatal SSL protocol error occurred");
	    if (backingError != 0) {
		Tls_Error(statePtr, ERR_reason_error_string(backingError));
	    } else if (SSL_get_verify_result(statePtr->ssl) != X509_V_OK) {
		Tls_Error(statePtr,
		    X509_verify_cert_error_string(SSL_get_verify_result(statePtr->ssl)));
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
	    statePtr->flags |= TLS_TCL_EOF;
	    break;

	case SSL_ERROR_WANT_READ:
	    /* Operation did not complete due to not enough data was available.
	       Retry again later. */
	    dprintf("Got SSL_ERROR_WANT_READ, mapping this to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    bytesRead = -1;
	    statePtr->want |= TCL_READABLE;
	    BIO_set_retry_read(statePtr->bio);
	    break;

	case SSL_ERROR_WANT_WRITE:
	    /* Operation did not complete due to unable to send all data to the
	       BIO. Retry again later. */
	    dprintf("Got SSL_ERROR_WANT_WRITE, mapping this to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    bytesRead = -1;
	    statePtr->want |= TCL_WRITABLE;
	    BIO_set_retry_write(statePtr->bio);
	    break;

	case SSL_ERROR_WANT_X509_LOOKUP:
	    /* The operation did not complete because an application callback
	       set by SSL_CTX_set_client_cert_cb() has asked to be called again. */
	    dprintf("Got SSL_ERROR_WANT_X509_LOOKUP, mapping it to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    bytesRead = -1;
	    break;

	case SSL_ERROR_SYSCALL:
	    /* Some non-recoverable, fatal I/O error occurred */
	    dprintf("SSL_ERROR_SYSCALL: Fatal I/O error occurred");

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
		Tls_Error(statePtr, Tcl_ErrnoMsg(*errorCodePtr));

	    } else {
		dprintf("I/O error occurred (backingError = %lu)", backingError);
		*errorCodePtr = Tcl_GetErrno();
		bytesRead = -1;
		Tls_Error(statePtr, ERR_reason_error_string(backingError));
	    }
	    statePtr->flags |= TLS_TCL_EOF;
	    break;

	case SSL_ERROR_ZERO_RETURN:
	    /* Peer has cleanly closed the connection by sending the close_notify
	       alert. Can't read, but can write. Need to return an EOF, so the
	       channel is closed which will send an SSL_shutdown(). */
	    dprintf("SSL_ERROR_ZERO_RETURN: Peer has closed the connection");
	    *errorCodePtr = 0;
	    bytesRead = 0;
	    statePtr->flags |= TLS_TCL_EOF;
	    Tls_Error(statePtr, "Peer has closed the connection for writing by sending the close_notify alert");
	    break;

	case SSL_ERROR_WANT_ASYNC:
	    /* Used with flag SSL_MODE_ASYNC, operation didn't complete because
	       an async engine is still processing data. */
	    dprintf("Got SSL_ERROR_WANT_ASYNC, mapping this to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    bytesRead = 0;
	    break;

	default:
	    /* Other error */
	    dprintf("Other error, abort");
	    *errorCodePtr = 0;
	    bytesRead = 0;
	    break;
    }

    dprintf("Input(%d) -> %d [%d]", bufSize, bytesRead, *errorCodePtr);
    return bytesRead;
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsOutputProc --
 *
 *	This procedure is invoked by the generic I/O layer to write data to the
 *	BIO whenever the the Tcl_Write(), Tcl_WriteChars, and Tcl_WriteObj
 *	functions are used. Equivalent to SSL_write_ex and SSL_write.
 *
 * Results:
 *	Returns the number of bytes written or -1 on error. Sets errorCodePtr
 *	to a POSIX error code if an error occurred, or 0 if successful.
 *
 * Side effects:
 *	Writes data to SSL/BIO.
 *
 *-----------------------------------------------------------------------------
 */
static int TlsOutputProc(
    ClientData instanceData,	/* Connection state info */
    const char *buf,		/* Buffer with data to write to BIO */
    int toWrite,		/* Size of data to write in bytes */
    int *errorCodePtr)		/* Storage for error code to return */
{
    unsigned long backingError;
    State *statePtr = (State *) instanceData;
    int written, err;
    *errorCodePtr = 0;

    dprintf("Write %d bytes", toWrite);
    dprintBuffer(buf, toWrite);

    /* Abort if the user verify callback is still running to avoid triggering
     * another call before the current one is complete. */
    if (statePtr->flags & TLS_TCL_CALLBACK) {
	dprintf("Don't process output while callbacks are running");
	written = -1;
	*errorCodePtr = EAGAIN;
	return -1;
    }

    /* If not initialized, do connect */
    /* Can also check SSL_is_init_finished(ssl) */
    if (statePtr->flags & TLS_TCL_INIT) {
	int tlsConnect;

	dprintf("Calling Tls_WaitForConnect");

	tlsConnect = Tls_WaitForConnect(statePtr, errorCodePtr, 1);
	if (tlsConnect < 0) {
	    dprintf("Got an error waiting to connect (tlsConnect = %i, *errorCodePtr = %i)",
		tlsConnect, *errorCodePtr);

	    written = -1;
	    if (*errorCodePtr == ECONNRESET) {
		dprintf("Got connection reset");
		/* Soft EOF */
		*errorCodePtr = 0;
		written = 0;
		statePtr->flags |= TLS_TCL_EOF;
	    }
	    return written;
	} else if (tlsConnect == 0) {
	    /* Try again */
	    written = -1;
	    return written;
	}
    }

    if (toWrite == 0) {
	dprintf("zero-write");
	err = BIO_flush(statePtr->bio);

	if (err <= 0) {
	    dprintf("Flushing failed");
	    Tls_Error(statePtr, "Flush failed");

	    *errorCodePtr = EIO;
	    written = 0;
	    return -1;
	}

	*errorCodePtr = 0;
	written = 0;
	return 0;
    }

    /*
     * We need to clear the SSL error stack now because we sometimes reach
     * this function with leftover errors in the stack.  If BIO_write
     * returns -1 and intends EAGAIN, there is a leftover error, it will be
     * misconstrued as an error, not EAGAIN.
     */
    dprintf("BIO_write: BIO pending=%d, Chan pending=%d", BIO_wpending(statePtr->bio), Tcl_OutputBuffered(statePtr->self));
    ERR_clear_error();
    BIO_clear_retry_flags(statePtr->bio);
    written = BIO_write(statePtr->bio, buf, toWrite);
    dprintf("BIO_write(%p, %d) -> [%d]", (void *) statePtr, toWrite, written);

    /* Same as SSL_want, but also checks the error queue */
    err = SSL_get_error(statePtr->ssl, written);
    backingError = ERR_get_error();

    if (written <= 0) {
	dprintf("Write failed: is EOF=%d, should retry=%d, retry read=%d, retry write=%d, other=%d",
	    BIO_eof(statePtr->bio),
	    BIO_should_retry(statePtr->bio), BIO_should_read(statePtr->bio),
	    BIO_should_write(statePtr->bio), BIO_should_io_special(statePtr->bio));
    } else {
	BIO_flush(statePtr->bio);
    }

    /* Based on error, do retry or abort */
    switch (err) {
	case SSL_ERROR_NONE:
	    /* I/O operation completed */
	    dprintf("SSL_ERROR_NONE");
	    if (written < 0) {
		written = 0;
	    }
	    break;

	case SSL_ERROR_SSL:
	    /* A non-recoverable, fatal error in the SSL library occurred,
	       usually a protocol error */
	    dprintf("SSL_ERROR_SSL: Fatal SSL protocol error occurred");
	    if (backingError != 0) {
		Tls_Error(statePtr, ERR_reason_error_string(backingError));
	    } else if (SSL_get_verify_result(statePtr->ssl) != X509_V_OK) {
		Tls_Error(statePtr,
		    X509_verify_cert_error_string(SSL_get_verify_result(statePtr->ssl)));
	    } else {
		Tls_Error(statePtr, "Unknown SSL error");
	    }
	    statePtr->flags |= TLS_TCL_EOF;
	    *errorCodePtr = ECONNABORTED;
	    written = -1;
	    break;

	case SSL_ERROR_WANT_READ:
	    /* Operation did not complete due to not enough data was available.
	       Retry again later with same data. */
	    dprintf("Got SSL_ERROR_WANT_READ, mapping it to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    written = -1;
	    statePtr->want |= TCL_READABLE;
	    BIO_set_retry_read(statePtr->bio);
	    break;

	case SSL_ERROR_WANT_WRITE:
	    /* Operation did not complete due to unable to send all data to the
	       BIO. Retry later with same data. */
	    dprintf("Got SSL_ERROR_WANT_WRITE, mapping it to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    written = -1;
	    statePtr->want |= TCL_WRITABLE;
	    BIO_set_retry_write(statePtr->bio);
	    break;

	case SSL_ERROR_WANT_X509_LOOKUP:
	    /* The operation did not complete because an application callback
	       set by SSL_CTX_set_client_cert_cb() has asked to be called again. */
	    dprintf("Got SSL_ERROR_WANT_X509_LOOKUP, mapping it to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    written = -1;
	    break;

	case SSL_ERROR_SYSCALL:
	    /* Some non-recoverable, fatal I/O error occurred */
	    dprintf("SSL_ERROR_SYSCALL: Fatal I/O error occurred");

	    if (backingError == 0 && written == 0) {
		dprintf("EOF reached")
		*errorCodePtr = 0;
		written = 0;
		Tls_Error(statePtr, "EOF reached");

	    } else if (backingError == 0 && written == -1) {
		dprintf("I/O error occurred (errno = %lu)", (unsigned long) Tcl_GetErrno());
		*errorCodePtr = Tcl_GetErrno();
		written = -1;
		Tls_Error(statePtr, Tcl_ErrnoMsg(*errorCodePtr));

	    } else {
		dprintf("I/O error occurred (backingError = %lu)", backingError);
		*errorCodePtr = Tcl_GetErrno();
		written = -1;
		Tls_Error(statePtr, ERR_reason_error_string(backingError));
	    }
	    statePtr->flags |= TLS_TCL_EOF;
	    break;

	case SSL_ERROR_ZERO_RETURN:
	    /* Peer has cleanly closed the connection by sending the close_notify
	       alert. Can't read, but can write. Need to return an EOF, so the
	       channel is closed which will send an SSL_shutdown(). */
	    dprintf("SSL_ERROR_ZERO_RETURN: Peer has closed the connection");
	    *errorCodePtr = 0;
	    written = 0;
	    statePtr->flags |= TLS_TCL_EOF;
	    Tls_Error(statePtr, "Peer has closed the connection for writing by sending the close_notify alert");
	    break;

	case SSL_ERROR_WANT_ASYNC:
	    /* Used with flag SSL_MODE_ASYNC, operation didn't complete because
	       an async engine is still processing data. */
	    dprintf("Got SSL_ERROR_WANT_ASYNC, mapping this to EAGAIN");
	    *errorCodePtr = EAGAIN;
	    written = 0;
	    break;

	default:
	    /* Other error */
	    dprintf("Other error, abort");
	    *errorCodePtr = 0;
	    written = 0;
	    break;
    }

    dprintf("Output(%d) -> %d", toWrite, written);
    return written;
}

/*
 *-----------------------------------------------------------------------------
 *
 * Tls_GetParent --
 *
 *	Get parent channel for a stacked channel.
 *
 * Results:
 *	Tcl_Channel or NULL if None
 *
 *-----------------------------------------------------------------------------
 */
Tcl_Channel Tls_GetParent(
    State *statePtr,		/* Connection state info */
    int maskFlags)		/* Which flags to process */
{
    dprintf("Requested to get parent of channel %p", statePtr->self);

    if ((statePtr->flags & ~maskFlags) & TLS_TCL_FASTPATH) {
	dprintf("Asked to get the parent channel while we are using FastPath -- returning NULL");
	return NULL;
    }
    return Tcl_GetStackedChannel(statePtr->self);
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsSetOptionProc --
 *
 *	Sets an option to value for a SSL socket based channel. Called by the
 *	generic I/O layer whenever the Tcl_SetChannelOption() function is used.
 *
 * Results:
 *	TCL_OK if successful or TCL_ERROR if failed.
 *
 * Side effects:
 *	Updates channel option to new value.
 *
 *-----------------------------------------------------------------------------
 */
static int
TlsSetOptionProc(
    ClientData instanceData,	/* Socket state. */
    Tcl_Interp *interp,		/* For errors - can be NULL. */
    const char *optionName,	/* Name of the option to set the value for, or
				 * NULL to get all options and their values. */
    const char *optionValue)	/* Value for option. */
{
    State *statePtr = (State *) instanceData;
    Tcl_Channel parent = Tls_GetParent(statePtr, TLS_TCL_FASTPATH);
    Tcl_DriverSetOptionProc *setOptionProc;

    dprintf("Called to set option %s to value %s", optionName, optionValue);

    /* Pass to parent */
    setOptionProc = Tcl_ChannelSetOptionProc(Tcl_GetChannelType(parent));
    if (setOptionProc != NULL) {
	return (*setOptionProc)(Tcl_GetChannelInstanceData(parent), interp, optionName, optionValue);
    }
    /*
     * Request for a specific option has to fail, we don't have any.
     */
    return Tcl_BadChannelOption(interp, optionName, "");
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsGetOptionProc --
 *
 *	Get a option's value for a SSL socket based channel, or a list of all
 *	options and their values. Called by the generic I/O layer whenever the
 *	Tcl_GetChannelOption() function is used.
 *
 *
 * Results:
 *	TCL_OK if successful or TCL_ERROR if failed. Sets optionValue to
 *	the option's value.
 *
 * Side effects:
 *	None
 *
 *-----------------------------------------------------------------------------
 */
static int
TlsGetOptionProc(
    ClientData instanceData,	/* Socket state. */
    Tcl_Interp *interp,		/* For errors - can be NULL. */
    const char *optionName,	/* Name of the option to retrieve the value for,
				 * or NULL to get all options and their values. */
    Tcl_DString *optionValue)	/* Where to store the computed value initialized by caller. */
{
    State *statePtr = (State *) instanceData;
    Tcl_Channel parent = Tls_GetParent(statePtr, TLS_TCL_FASTPATH);
    Tcl_DriverGetOptionProc *getOptionProc;

    dprintf("Called to get option %s", optionName);

    /* Pass to parent */
    getOptionProc = Tcl_ChannelGetOptionProc(Tcl_GetChannelType(parent));
    if (getOptionProc != NULL) {
	return (*getOptionProc)(Tcl_GetChannelInstanceData(parent), interp,
	    optionName, optionValue);
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
 *-----------------------------------------------------------------------------
 *
 * TlsChannelHandlerTimer --
 *
 *	Called by the notifier via a timer, to generate read/write events to
 *	flush out data waiting in channel buffers. Called by TlsWatchProc to
 *	periodically check for new events. Used to generate events when data is
 *	buffered in BIO and there are no underlying channel events.
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Creates notification event.
 *
 *-----------------------------------------------------------------------------
 */
static void TlsChannelHandlerTimer(
    ClientData clientData)	/* Socket state. */
{
    State *statePtr = (State *) clientData;
    int mask = statePtr->want; /* Init to SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE */

    dprintf("Called with mask 0x%02x", mask);

    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	statePtr->timer = (Tcl_TimerToken) NULL;
	Tcl_Release((ClientData) statePtr);
    }

    /* Check for amount of data pending in IO or BIO write buffer */
    if (Tcl_OutputBuffered(statePtr->self) || BIO_wpending(statePtr->bio)) {
	dprintf("[chan=%p] BIO writable", statePtr->self);

	mask |= TCL_WRITABLE;
    }

    /* Check for amount of data pending in IO or BIO read buffer */
    if (Tcl_InputBuffered(statePtr->self) || BIO_pending(statePtr->bio)) {
	dprintf("[chan=%p] BIO readable", statePtr->self);

	mask |= TCL_READABLE;
    }

    /* Notify the generic IO layer that mask events have occurred on the channel */
    if (mask > 0) {
	dprintf("Notifying ourselves with mask=%d", mask);
	Tcl_NotifyChannel(statePtr->self, mask);
    } else {
	dprintf("No notification");
    }
    statePtr->want = 0;
    return;
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsWatchProc --
 *
 *	Set up the event notifier to watch for events of interest from this
 *	channel. Called by the generic I/O layer whenever the user (or the
 *	system) announces its (dis)interest in events on the channel. This is
 *	called repeatedly.
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Sets up or clears a time-based notifier so that future events on the
 *	channel will be seen by TCL.
 *
 *-----------------------------------------------------------------------------
 */
static void
TlsWatchProc(
    ClientData instanceData,	/* Connection state info */
    int mask)			/* Events of interest; an OR-ed combination of
				 * TCL_READABLE, TCL_WRITABLE and TCL_EXCEPTION. */
{
    Tcl_Channel parent;
    State *statePtr = (State *) instanceData;
    Tcl_DriverWatchProc *watchProc;

    dprintf("Called with mask 0x%02x and want 0x%02x", mask, statePtr->want);
    dprintFlags(statePtr);

    /* Abort if the user verify callback is still running to avoid triggering
     * another call before the current one is complete. */
    if (statePtr->flags & TLS_TCL_CALLBACK) {
	dprintf("Callback is on-going, doing nothing");
	return;
    }

    /* Get channel to monitor for events */
    parent = Tls_GetParent(statePtr, TLS_TCL_FASTPATH);
    dprintf("Parent: chan buffer=%d, input buffer=%d, output buffer=%d", \
	Tcl_ChannelBuffered(parent), Tcl_InputBuffered(parent), Tcl_OutputBuffered(parent));

    /* Abort if connect failed */
    if (statePtr->flags & TLS_TCL_HANDSHAKE_FAILED) {
	dprintf("Asked to watch a socket with a failed handshake -- nothing can happen here");
	dprintf("Unregistering interest in the lower channel");

	watchProc = Tcl_ChannelWatchProc(Tcl_GetChannelType(parent));
	watchProc(Tcl_GetChannelInstanceData(parent), 0);
	statePtr->watchMask = 0;
	return;
    }

    statePtr->watchMask = mask;

    /*
     * No channel handlers any more. We will be notified automatically about
     * events on the channel below via a call to our 'TransformNotifyProc'. But
     * we have to pass the interest down now. We are allowed to add additional
     * 'interest' to the mask if we want to, but this transformation has no
     * such interest. It just passes the request down, unchanged.
     */
    dprintf("Registering our interest in the lower channel (chan=%p)", (void *) parent);
    watchProc = Tcl_ChannelWatchProc(Tcl_GetChannelType(parent));
    watchProc(Tcl_GetChannelInstanceData(parent), mask);

    /* Schedule next event if data is pending, otherwise cease events for now */
    if (!(mask & TCL_READABLE)) {
	/* Remove timer, if any */
	if (statePtr->timer != (Tcl_TimerToken) NULL) {
	    dprintf("A timer was found, deleting it");
	    Tcl_DeleteTimerHandler(statePtr->timer);
	    statePtr->timer = (Tcl_TimerToken) NULL;
	    Tcl_Release((ClientData) statePtr);
	}

    /* Don't check for pending data here, will check for want in timer callback */
    } else {
	/* Add timer, if none */
	if (statePtr->timer == (Tcl_TimerToken) NULL) {
	    dprintf("Creating a new timer since data appears to be waiting");
	    Tcl_Preserve((ClientData) statePtr);
	    statePtr->timer = Tcl_CreateTimerHandler(TLS_TCL_DELAY, TlsChannelHandlerTimer, (ClientData) statePtr);
	}
    }
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsGetHandleProc --
 *
 *	This procedure is invoked by the generic IO level to retrieve an OS
 *	specific handle associated with the channel. Not used for transforms.
 *
 * Results:
 *	The appropriate Tcl_File handle or NULL if None
 *
 * Side effects:
 *	None
 *
 *-----------------------------------------------------------------------------
 */
static int TlsGetHandleProc(
    ClientData instanceData,	/* Socket state. */
    int direction,		/* TCL_READABLE or TCL_WRITABLE */
    ClientData *handlePtr)	/* Handle associated with the channel */
{
    State *statePtr = (State *) instanceData;

    dprintf("Called with direction 0x%02x", direction);

    return Tcl_GetChannelHandle(Tls_GetParent(statePtr, TLS_TCL_FASTPATH),
	direction, handlePtr);
}

/*
 *-----------------------------------------------------------------------------
 *
 * TlsNotifyProc --
 *
 *	This procedure is invoked by the generic IO level to notify the channel
 *	that an event has occurred on the underlying channel. It is used by
 *	stacked channel drivers that wish to be notified of events that occur
 *	on the underlying (stacked) channel.
 *
 * Results:
 *	Returns mask value to indicate none of the events were serviced.
 *
 * Side effects:
 *	May call Tls_WaitForConnect and/or delete timer.
 *
 *-----------------------------------------------------------------------------
 */
static int TlsNotifyProc(
    ClientData instanceData,	/* Socket state. */
    int mask)			/* type of event that occurred: OR-ed
				 * combination of TCL_READABLE or TCL_WRITABLE */
{
    State *statePtr = (State *) instanceData;
    int errorCode = 0;

    dprintf("Called with mask 0x%02x", mask);

    /* Abort if the user verify callback is still running to avoid triggering
     * another call before the current one is complete. */
    if (statePtr->flags & TLS_TCL_CALLBACK) {
	dprintf("Callback is on-going, returning failed");
	return 0;
    }

    /* If not initialized, do connect */
    if (statePtr->flags & TLS_TCL_INIT) {
	int tlsConnect;

	dprintf("Calling Tls_WaitForConnect");

	tlsConnect = Tls_WaitForConnect(statePtr, &errorCode, 1);
	if (tlsConnect < 1) {
	    dprintf("Got an error waiting to connect (tlsConnect = %i, *errorCodePtr = %i)", tlsConnect, errorCode);
	    if (errorCode == EAGAIN) {
		dprintf("Async flag could be set (didn't check) and errorCode == EAGAIN:  Returning failed");

		return 0;
	    }

	    dprintf("Tls_WaitForConnect returned an error");
	}
    }

    /*
     * Delete an existing timer. It was not fired, yet we are here, so the
     * below channel generated such an event and we don't need to. The renewal
     * of the interest after the execution of channel handlers will eventually
     * cause us to recreate the timer (in TlsWatchProc).
     */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = (Tcl_TimerToken) NULL;
	Tcl_Release((ClientData) statePtr);
    }

    /*
     * An event occurred in the underlying channel. This transformation doesn't
     * process such events thus returns the incoming mask unchanged.
     */
    dprintf("Returning %i", mask);
    return mask;
}

/*
 *-----------------------------------------------------------------------------
 *
 * Tls_ChannelType --
 *
 *	Defines the TLS channel driver handlers for this channel type.
 *
 * Results:
 *	Returns a pointer to Tcl_ChannelType structure.
 *
 * Side effects:
 *	None
 *
 *-----------------------------------------------------------------------------
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
