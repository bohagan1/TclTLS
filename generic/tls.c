/*
 * Copyright (C) 1997-1999 Matt Newman <matt@novadigm.com>
 * some modifications:
 *	Copyright (C) 2000 Ajuba Solutions
 *	Copyright (C) 2002 ActiveState Corporation
 *	Copyright (C) 2004 Starfish Systems
 *	Copyright (C) 2023 Brian O'Hagan
 *
 * TLS (aka SSL) Channel - can be layered on any bi-directional
 * Tcl_Channel (Note: Requires Trf Core Patch)
 *
 * This was built (almost) from scratch based upon observation of
 * OpenSSL 0.9.2B
 *
 * Addition credit is due for Andreas Kupries (a.kupries@westend.com), for
 * providing the Tcl_ReplaceChannel mechanism and working closely with me
 * to enhance it to support full fileevent semantics.
 *
 * Also work done by the follow people provided the impetus to do this "right":
 *	tclSSL (Colin McCormack, Shared Technology)
 *	SSLtcl (Peter Antman)
 *
 */

#include "tlsInt.h"
#include "tclOpts.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>

/* Min OpenSSL version */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "Only OpenSSL v1.1.1 or later is supported"
#endif

/*
 * External functions
 */

/*
 * Forward declarations
 */

#define F2N(key, dsp) \
	(((key) == NULL) ? (char *) NULL : \
		Tcl_TranslateFileName(interp, (key), (dsp)))

static SSL_CTX *CTX_Init(State *statePtr, int isServer, int proto, char *key,
		char *certfile, unsigned char *key_asn1, unsigned char *cert_asn1,
		int key_asn1_len, int cert_asn1_len, char *CAdir, char *CAfile,
		char *ciphers, char *ciphersuites, int level, char *DHparams);

static int	TlsLibInit(int uninitialize);

#define TLS_PROTO_SSL2		0x01
#define TLS_PROTO_SSL3		0x02
#define TLS_PROTO_TLS1		0x04
#define TLS_PROTO_TLS1_1	0x08
#define TLS_PROTO_TLS1_2	0x10
#define TLS_PROTO_TLS1_3	0x20
#define ENABLED(flag, mask)	(((flag) & (mask)) == (mask))

#define SSLKEYLOGFILE		"SSLKEYLOGFILE"

/*
 * Static data structures
 */

#ifndef OPENSSL_NO_DH
#include "dh_params.h"
#endif

/*
 * Thread-Safe TLS Code
 */

#ifdef TCL_THREADS
#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>

#ifdef OPENSSL_THREADS
#include <openssl/crypto.h>
#include <openssl/ssl.h>

/*
 * Threaded operation requires locking callbacks
 * Based from /crypto/cryptlib.c of OpenSSL and NSOpenSSL.
 */

static Tcl_Mutex *locks = NULL;
static int locksCount = 0;
static Tcl_Mutex init_mx;
#endif /* OPENSSL_THREADS */
#endif /* TCL_THREADS */


/********************/
/* Callbacks        */
/********************/

/*
 *-------------------------------------------------------------------
 *
 * Eval Callback Command --
 *
 *	Eval callback command and catch any errors
 *
 * Results:
 *	0 = Command returned fail or eval returned TCL_ERROR
 *	1 = Command returned success or eval returned TCL_OK
 *
 * Side effects:
 *	Evaluates callback command
 *
 *-------------------------------------------------------------------
 */
static int
EvalCallback(Tcl_Interp *interp, State *statePtr, Tcl_Obj *cmdPtr) {
    int code, ok = 0;

    Tcl_Preserve((ClientData) interp);
    Tcl_Preserve((ClientData) statePtr);

    /* Eval callback with success for ok or return value 1, fail for error or return value 0 */
    Tcl_ResetResult(interp);
    code = Tcl_EvalObjEx(interp, cmdPtr, TCL_EVAL_GLOBAL);
    if (code == TCL_OK) {
	/* Check result for return value */
	Tcl_Obj *result = Tcl_GetObjResult(interp);
	if (result == NULL || Tcl_GetIntFromObj(interp, result, &ok) != TCL_OK) {
	    ok = 1;
	}
    } else {
	/* Error - reject the certificate */
#if (TCL_MAJOR_VERSION == 8) && (TCL_MINOR_VERSION < 6)
	Tcl_BackgroundError(interp);
#else
	Tcl_BackgroundException(interp, code);
#endif
    }

    Tcl_Release((ClientData) statePtr);
    Tcl_Release((ClientData) interp);
    return ok;
}

/*
 *-------------------------------------------------------------------
 *
 * InfoCallback --
 *
 *	Monitors SSL connection process
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *
 *-------------------------------------------------------------------
 */
static void
InfoCallback(const SSL *ssl, int where, int ret) {
    State *statePtr = (State*)SSL_get_app_data((SSL *)ssl);
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    char *major; char *minor;

    dprintf("Called");

    if (statePtr->callback == (Tcl_Obj*)NULL)
	return;

    if (where & SSL_CB_HANDSHAKE_START) {
	major = "handshake";
	minor = "start";
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
	major = "handshake";
	minor = "done";
    } else {
	if (where & SSL_CB_ALERT)		major = "alert";
	else if (where & SSL_ST_CONNECT)	major = "connect";
	else if (where & SSL_ST_ACCEPT)		major = "accept";
	else					major = "unknown";

	if (where & SSL_CB_READ)		minor = "read";
	else if (where & SSL_CB_WRITE)		minor = "write";
	else if (where & SSL_CB_LOOP)		minor = "loop";
	else if (where & SSL_CB_EXIT)		minor = "exit";
	else					minor = "unknown";
    }

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->callback);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("info", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(major, -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(minor, -1));

    if (where & SSL_CB_ALERT) {
	Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(SSL_alert_desc_string_long(ret), -1));
	Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(SSL_alert_type_string_long(ret), -1));
    } else {
	Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(SSL_state_string_long(ssl), -1));
	Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("info", -1));
    }

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    EvalCallback(interp, statePtr, cmdPtr);
    Tcl_DecrRefCount(cmdPtr);
}

/*
 *-------------------------------------------------------------------
 *
 * MessageCallback --
 *
 *	Monitors SSL protocol messages
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *
 *-------------------------------------------------------------------
 */
#ifndef OPENSSL_NO_SSL_TRACE
static void
MessageCallback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    State *statePtr = (State*)arg;
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    char *ver, *type;
    BIO *bio;
    char buffer[15000];
    buffer[0] = 0;

    dprintf("Called");

    if (statePtr->callback == (Tcl_Obj*)NULL)
	return;

    switch(version) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(NO_SSL2) && !defined(OPENSSL_NO_SSL2)
    case SSL2_VERSION:
	ver = "SSLv2";
	break;
#endif
#if !defined(NO_SSL3) && !defined(OPENSSL_NO_SSL3)
    case SSL3_VERSION:
	ver = "SSLv3";
	break;
#endif
    case TLS1_VERSION:
	ver = "TLSv1";
	break;
    case TLS1_1_VERSION:
	ver = "TLSv1.1";
	break;
    case TLS1_2_VERSION:
	ver = "TLSv1.2";
	break;
    case TLS1_3_VERSION:
	ver = "TLSv1.3";
	break;
    case 0:
	ver = "none";
	break;
    default:
	ver = "unknown";
	break;
    }

    switch (content_type) {
    case SSL3_RT_HEADER:
	type = "Header";
	break;
    case SSL3_RT_INNER_CONTENT_TYPE:
	type = "Inner Content Type";
	break;
    case SSL3_RT_CHANGE_CIPHER_SPEC:
	type = "Change Cipher";
	break;
    case SSL3_RT_ALERT:
	type = "Alert";
	break;
    case SSL3_RT_HANDSHAKE:
	type = "Handshake";
	break;
    case SSL3_RT_APPLICATION_DATA:
	type = "App Data";
	break;
    case DTLS1_RT_HEARTBEAT:
	type = "Heartbeat";
	break;
    default:
	type = "unknown";
    }

    /* Needs compile time option "enable-ssl-trace". */
    if ((bio = BIO_new(BIO_s_mem())) != NULL) {
	int n;
	SSL_trace(write_p, version, content_type, buf, len, ssl, (void *)bio);
	n = BIO_read(bio, buffer, min(BIO_pending(bio), 14999));
	n = (n<0) ? 0 : n;
	buffer[n] = 0;
	(void)BIO_flush(bio);
	BIO_free(bio);
   }

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->callback);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("message", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(write_p ? "Sent" : "Received", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(ver, -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(type, -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(buffer, -1));

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    EvalCallback(interp, statePtr, cmdPtr);
    Tcl_DecrRefCount(cmdPtr);
}
#endif

/*
 *-------------------------------------------------------------------
 *
 * VerifyCallback --
 *
 *	Monitors SSL certificate validation process. Used to control the
 *	behavior when the SSL_VERIFY_PEER flag is set. This is called
 *	whenever a certificate is inspected or decided invalid. Called for
 *	each certificate in the cert chain.
 *
 * Checks:
 *	certificate chain is checked starting with the deepest nesting level
 *	  (the root CA certificate) and worked upward to the peer's certificate.
 *	All signatures are valid, current time is within first and last validity time.
 *	Check that the certificate is issued by the issuer certificate issuer.
 *	Check the revocation status for each certificate.
 *	Check the validity of the given CRL and the cert revocation status.
 *	Check the policies of all the certificates
 *
 * Args
 *	preverify_ok indicates whether the certificate verification passed (1) or not (0)
 *
 * Results:
 *	A callback bound to the socket may return one of:
 *	    0			- the certificate is deemed invalid, send verification
 *				  failure alert to peer, and terminate handshake.
 *	    1			- the certificate is deemed valid, continue with handshake.
 *	    empty string	- no change to certificate validation
 *
 * Side effects:
 *	The err field of the currently operative State is set
 *	  to a string describing the SSL negotiation failure reason
 *
 *-------------------------------------------------------------------
 */
static int
VerifyCallback(int ok, X509_STORE_CTX *ctx) {
    Tcl_Obj *cmdPtr;
    SSL   *ssl		= (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    X509  *cert		= X509_STORE_CTX_get_current_cert(ctx);
    State *statePtr	= (State*)SSL_get_app_data(ssl);
    Tcl_Interp *interp	= statePtr->interp;
    int depth		= X509_STORE_CTX_get_error_depth(ctx);
    int err		= X509_STORE_CTX_get_error(ctx);

    dprintf("Verify: %d", ok);

    if (statePtr->vcmd == (Tcl_Obj*)NULL) {
	if (statePtr->vflags & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
	    return ok;
	} else {
	    return 1;
	}
    } else if (cert == NULL || ssl == NULL) {
	return 0;
    }

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->vcmd);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("verify", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewIntObj(depth));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tls_NewX509Obj(interp, cert));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewIntObj(ok));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	Tcl_NewStringObj((char*)X509_verify_cert_error_string(err), -1));

    /* Prevent I/O while callback is in progress */
    /* statePtr->flags |= TLS_TCL_CALLBACK; */

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    ok = EvalCallback(interp, statePtr, cmdPtr);
    Tcl_DecrRefCount(cmdPtr);

    /* statePtr->flags &= ~(TLS_TCL_CALLBACK); */
    return(ok);	/* By default, leave verification unchanged. */
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Error --
 *
 *	Calls callback with list of errors.
 *
 * Side effects:
 *	The err field of the currently operative State is set
 *	  to a string describing the SSL negotiation failure reason
 *
 *-------------------------------------------------------------------
 */
void
Tls_Error(State *statePtr, char *msg) {
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr, *listPtr;
    unsigned long err;
    statePtr->err = msg;

    dprintf("Called");

    if (statePtr->callback == (Tcl_Obj*)NULL)
	return;

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->callback);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("error", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));
    if (msg != NULL) {
	Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(msg, -1));

    } else if ((msg = Tcl_GetStringFromObj(Tcl_GetObjResult(interp), NULL)) != NULL) {
	Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(msg, -1));

    } else {
	listPtr = Tcl_NewListObj(0, NULL);
	while ((err = ERR_get_error()) != 0) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj(ERR_reason_error_string(err), -1));
	}
	Tcl_ListObjAppendElement(interp, cmdPtr, listPtr);
    }

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    EvalCallback(interp, statePtr, cmdPtr);
    Tcl_DecrRefCount(cmdPtr);
}

/*
 *-------------------------------------------------------------------
 *
 * KeyLogCallback --
 *
 *	Write received key data to log file.
 *
 * Side effects:
 *	none
 *
 *-------------------------------------------------------------------
 */
void KeyLogCallback(const SSL *ssl, const char *line) {
    char *str = getenv(SSLKEYLOGFILE);
    FILE *fd;

    dprintf("Called");

    if (str) {
	fd = fopen(str, "a");
	fprintf(fd, "%s\n",line);
	fclose(fd);
    }
}

/*
 *-------------------------------------------------------------------
 *
 * Password Callback --
 *
 *	Called when a password for a private key loading/storing a PEM
 *	certificate with encryption. Evals callback script and returns
 *	the result as the password string in buf.
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *
 * Returns:
 *	Password size in bytes or -1 for an error.
 *
 *-------------------------------------------------------------------
 */
static int
PasswordCallback(char *buf, int size, int rwflag, void *udata) {
    State *statePtr	= (State *) udata;
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    int code;

    dprintf("Called");

    /* If no callback, use default callback */
    if (statePtr->password == NULL) {
	if (Tcl_EvalEx(interp, "tls::password", -1, TCL_EVAL_GLOBAL) == TCL_OK) {
	    char *ret = (char *) Tcl_GetStringResult(interp);
	    strncpy(buf, ret, (size_t) size);
	    return (int)strlen(ret);
	} else {
	    return -1;
	}
    }

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->password);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("password", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewIntObj(rwflag));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewIntObj(size));

    Tcl_Preserve((ClientData) interp);
    Tcl_Preserve((ClientData) statePtr);

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    code = Tcl_EvalObjEx(interp, cmdPtr, TCL_EVAL_GLOBAL);
    if (code != TCL_OK) {
#if (TCL_MAJOR_VERSION == 8) && (TCL_MINOR_VERSION < 6)
	Tcl_BackgroundError(interp);
#else
	Tcl_BackgroundException(interp, code);
#endif
    }
    Tcl_DecrRefCount(cmdPtr);

    Tcl_Release((ClientData) statePtr);

    /* If successful, pass back password string and truncate if too long */
    if (code == TCL_OK) {
	int len;
	char *ret = (char *) Tcl_GetStringFromObj(Tcl_GetObjResult(interp), &len);
	if (len > size-1) {
	    len = size-1;
	}
	strncpy(buf, ret, (size_t) len);
	buf[len] = '\0';
	Tcl_Release((ClientData) interp);
	return(len);
    }
    Tcl_Release((ClientData) interp);
    return -1;
}

/*
 *-------------------------------------------------------------------
 *
 * Session Callback for Clients --
 *
 *	Called when a new session is added to the cache. In TLS 1.3
 *	this may be received multiple times after the handshake. For
 *	earlier versions, this will be received during the handshake.
 *	This is the preferred way to obtain a resumable session.
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *
 * Return codes:
 *	0 = error where session will be immediately removed from the internal cache.
 *	1 = success where app retains session in session cache, and must call SSL_SESSION_free() when done.
 *
 *-------------------------------------------------------------------
 */
static int
SessionCallback(const SSL *ssl, SSL_SESSION *session) {
    State *statePtr = (State*)SSL_get_app_data((SSL *)ssl);
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    const unsigned char *ticket;
    const unsigned char *session_id;
    size_t len2;
    unsigned int ulen;

    dprintf("Called");

    if (statePtr->callback == (Tcl_Obj*)NULL) {
	return SSL_TLSEXT_ERR_OK;
    } else if (ssl == NULL) {
	return SSL_TLSEXT_ERR_NOACK;
    }

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->callback);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("session", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));

    /* Session id */
    session_id = SSL_SESSION_get_id(session, &ulen);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewByteArrayObj(session_id, (int) ulen));

    /* Session ticket */
    SSL_SESSION_get0_ticket(session, &ticket, &len2);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewByteArrayObj(ticket, (int) len2));

    /* Lifetime - number of seconds */
    Tcl_ListObjAppendElement(interp, cmdPtr,
	Tcl_NewLongObj((long) SSL_SESSION_get_ticket_lifetime_hint(session)));

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    EvalCallback(interp, statePtr, cmdPtr);
    Tcl_DecrRefCount(cmdPtr);
    return 0;
}

/*
 *-------------------------------------------------------------------
 *
 * ALPN Callback for Servers and NPN Callback for Clients --
 *
 *	Perform protocol (http/1.1, h2, h3, etc.) selection for the
 *	incoming connection. Called after Hello and server callbacks.
 *	Where 'out' is selected protocol and 'in' is the peer advertised list.
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *
 * Return codes:
 *	SSL_TLSEXT_ERR_OK: ALPN protocol selected. The connection continues.
 *	SSL_TLSEXT_ERR_ALERT_FATAL: There was no overlap between the client's
 *	    supplied list and the server configuration. The connection will be aborted.
 *	SSL_TLSEXT_ERR_NOACK: ALPN protocol not selected, e.g., because no ALPN
 *	    protocols are configured for this connection. The connection continues.
 *
 *-------------------------------------------------------------------
 */
static int
ALPNCallback(const SSL *ssl, const unsigned char **out, unsigned char *outlen,
	const unsigned char *in, unsigned int inlen, void *arg) {
    State *statePtr = (State*)arg;
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    int code, res;

    dprintf("Called");

    if (ssl == NULL || arg == NULL) {
	return SSL_TLSEXT_ERR_NOACK;
    }

    /* Select protocol */
    if (SSL_select_next_proto(out, outlen, statePtr->protos, statePtr->protos_len,
	in, inlen) == OPENSSL_NPN_NEGOTIATED) {
	/* Match found */
	res = SSL_TLSEXT_ERR_OK;
    } else {
	/* OPENSSL_NPN_NO_OVERLAP = No overlap, so use first item from client protocol list */
	res = SSL_TLSEXT_ERR_NOACK;
    }

    if (statePtr->vcmd == (Tcl_Obj*)NULL) {
	return res;
    }

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->vcmd);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("alpn", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(*out, -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewBooleanObj(res == SSL_TLSEXT_ERR_OK));

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    if ((code = EvalCallback(interp, statePtr, cmdPtr)) > 1) {
	res = SSL_TLSEXT_ERR_NOACK;
    } else if (code == 1) {
	res = SSL_TLSEXT_ERR_OK;
    } else {
	res = SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    Tcl_DecrRefCount(cmdPtr);
    return res;
}

/*
 *-------------------------------------------------------------------
 *
 * Advertise Protocols Callback for Next Protocol Negotiation (NPN) in ServerHello --
 *
 *	called when a TLS server needs a list of supported protocols for Next
 *	Protocol Negotiation.
 *
 * Results:
 *	None
 *
 * Side effects:
 *
 * Return codes:
 *	SSL_TLSEXT_ERR_OK: NPN protocol selected. The connection continues.
 *	SSL_TLSEXT_ERR_NOACK: NPN protocol not selected. The connection continues.
 *
 *-------------------------------------------------------------------
 */
#ifdef USE_NPN
static int
NPNCallback(const SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg) {
    State *statePtr = (State*)arg;

    dprintf("Called");

    if (ssl == NULL || arg == NULL) {
	return SSL_TLSEXT_ERR_NOACK;
    }

    /* Set protocols list */
    if (statePtr->protos != NULL) {
	*out = statePtr->protos;
	*outlen = statePtr->protos_len;
    } else {
	*out = NULL;
	*outlen = 0;
	return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

/*
 *-------------------------------------------------------------------
 *
 * SNI Callback for Servers --
 *
 *	Perform server-side SNI hostname selection after receiving SNI extension
 *	in Client Hello. Called after hello callback but before ALPN callback.
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *
 * Return codes:
 *	SSL_TLSEXT_ERR_OK: SNI hostname is accepted. The connection continues.
 *	SSL_TLSEXT_ERR_ALERT_FATAL: SNI hostname is not accepted. The connection
 *	    is aborted. Default for alert is SSL_AD_UNRECOGNIZED_NAME.
 *	SSL_TLSEXT_ERR_ALERT_WARNING: SNI hostname is not accepted, warning alert
 *	    sent (not supported in TLSv1.3). The connection continues.
 *	SSL_TLSEXT_ERR_NOACK: SNI hostname is not accepted and not acknowledged,
 *	    e.g. if SNI has not been configured. The connection continues.
 *
 *-------------------------------------------------------------------
 */
static int
SNICallback(const SSL *ssl, int *alert, void *arg) {
    State *statePtr = (State*)arg;
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    int code, res;
    char *servername = NULL;

    dprintf("Called");

    if (ssl == NULL || arg == NULL) {
	return SSL_TLSEXT_ERR_NOACK;
    }

    /* Only works for TLS 1.2 and earlier */
    servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername || servername[0] == '\0') {
	return SSL_TLSEXT_ERR_NOACK;
    }

    if (statePtr->vcmd == (Tcl_Obj*)NULL) {
	return SSL_TLSEXT_ERR_OK;
    }

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->vcmd);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("sni", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(servername , -1));

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    if ((code = EvalCallback(interp, statePtr, cmdPtr)) > 1) {
	res = SSL_TLSEXT_ERR_ALERT_WARNING;
	*alert = SSL_AD_UNRECOGNIZED_NAME; /* Not supported by TLS 1.3 */
    } else if (code == 1) {
	res = SSL_TLSEXT_ERR_OK;
    } else {
	res = SSL_TLSEXT_ERR_ALERT_FATAL;
	*alert = SSL_AD_UNRECOGNIZED_NAME; /* Not supported by TLS 1.3 */
    }
    Tcl_DecrRefCount(cmdPtr);
    return res;
}

/*
 *-------------------------------------------------------------------
 *
 * ClientHello Handshake Callback for Servers --
 *
 *	Used by server to examine the server name indication (SNI) extension
 *	provided by the client in order to select an appropriate certificate to
 *	present, and make other configuration adjustments relevant to that server
 *	name and its configuration. This includes swapping out the associated
 *	SSL_CTX pointer, modifying the server's list of permitted TLS versions,
 *	changing the server's cipher list in response to the client's cipher list, etc.
 *	Called before SNI and ALPN callbacks.
 *
 * Results:
 *	None
 *
 * Side effects:
 *	Calls callback (if defined)
 *
 * Return codes:
 *	SSL_CLIENT_HELLO_RETRY: suspend the handshake, and the handshake function will return immediately
 *	SSL_CLIENT_HELLO_ERROR: failure, terminate connection. Set alert to error code.
 *	SSL_CLIENT_HELLO_SUCCESS: success
 *
 *-------------------------------------------------------------------
 */
static int
HelloCallback(const SSL *ssl, int *alert, void *arg) {
    State *statePtr = (State*)arg;
    Tcl_Interp *interp	= statePtr->interp;
    Tcl_Obj *cmdPtr;
    int code, res;
    const char *servername;
    const unsigned char *p;
    size_t len, remaining;

    dprintf("Called");

    if (statePtr->vcmd == (Tcl_Obj*)NULL) {
	return SSL_CLIENT_HELLO_SUCCESS;
    } else if (ssl == (const SSL *)NULL || arg == (void *)NULL) {
	return SSL_CLIENT_HELLO_ERROR;
    }

    /* Get names */
    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &p, &remaining) || remaining <= 2) {
	*alert = SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER;
	return SSL_CLIENT_HELLO_ERROR;
    }

    /* Extract the length of the supplied list of names. */
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 != remaining) {
	*alert = SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER;
	return SSL_CLIENT_HELLO_ERROR;
    }
    remaining = len;

    /* The list in practice only has a single element, so we only consider the first one. */
    if (remaining == 0 || *p++ != TLSEXT_NAMETYPE_host_name) {
	*alert = SSL_R_TLSV1_ALERT_INTERNAL_ERROR;
	return SSL_CLIENT_HELLO_ERROR;
    }
    remaining--;

    /* Now we can finally pull out the byte array with the actual hostname. */
    if (remaining <= 2) {
	*alert = SSL_R_TLSV1_ALERT_INTERNAL_ERROR;
	return SSL_CLIENT_HELLO_ERROR;
    }
    len = (*(p++) << 8);
    len += *(p++);
    if (len + 2 > remaining) {
	*alert = SSL_R_TLSV1_ALERT_INTERNAL_ERROR;
	return SSL_CLIENT_HELLO_ERROR;
    }
    remaining = len;
    servername = (const char *)p;

    /* Create command to eval */
    cmdPtr = Tcl_DuplicateObj(statePtr->vcmd);
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj("hello", -1));
    Tcl_ListObjAppendElement(interp, cmdPtr,
	    Tcl_NewStringObj(Tcl_GetChannelName(statePtr->self), -1));
    Tcl_ListObjAppendElement(interp, cmdPtr, Tcl_NewStringObj(servername, (int) len));

    /* Eval callback command */
    Tcl_IncrRefCount(cmdPtr);
    if ((code = EvalCallback(interp, statePtr, cmdPtr)) > 1) {
	res = SSL_CLIENT_HELLO_RETRY;
	*alert = SSL_R_TLSV1_ALERT_USER_CANCELLED;
    } else if (code == 1) {
	res = SSL_CLIENT_HELLO_SUCCESS;
    } else {
	res = SSL_CLIENT_HELLO_ERROR;
	*alert = SSL_R_TLSV1_ALERT_INTERNAL_ERROR;
    }
    Tcl_DecrRefCount(cmdPtr);
    return res;
}

/********************/
/* Commands         */
/********************/

/*
 *-------------------------------------------------------------------
 *
 * HandshakeObjCmd --
 *
 *	This command is used to verify whether the handshake is complete
 *	or not.
 *
 * Results:
 *	A standard Tcl result. 1 means handshake complete, 0 means pending.
 *
 * Side effects:
 *	May force SSL negotiation to take place.
 *
 *-------------------------------------------------------------------
 */
static int HandshakeObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Channel chan;        /* The channel to set a mode on. */
    State *statePtr;        /* client state for ssl socket */
    const char *errStr = NULL;
    int ret = 1;
    int err = 0;

    dprintf("Called");

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return(TCL_ERROR);
    }

    ERR_clear_error();

    chan = Tcl_GetChannel(interp, Tcl_GetStringFromObj(objv[1], NULL), NULL);
    if (chan == (Tcl_Channel) NULL) {
	return(TCL_ERROR);
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
	    "\": not a TLS channel", NULL);
	Tcl_SetErrorCode(interp, "TLS", "HANDSHAKE", "CHANNEL", "INVALID", (char *) NULL);
	return(TCL_ERROR);
    }
    statePtr = (State *)Tcl_GetChannelInstanceData(chan);

    dprintf("Calling Tls_WaitForConnect");
    ret = Tls_WaitForConnect(statePtr, &err, 1);
    dprintf("Tls_WaitForConnect returned: %i", ret);

    if (ret < 0 && ((statePtr->flags & TLS_TCL_ASYNC) && (err == EAGAIN))) {
	dprintf("Async set and err = EAGAIN");
	ret = 0;
    } else if (ret < 0) {
	long result;
	errStr = statePtr->err;
	Tcl_ResetResult(interp);
	Tcl_SetErrno(err);

	if (!errStr || (*errStr == 0)) {
	    errStr = Tcl_PosixError(interp);
	}

	Tcl_AppendResult(interp, "handshake failed: ", errStr, (char *) NULL);
	if ((result = SSL_get_verify_result(statePtr->ssl)) != X509_V_OK) {
	    Tcl_AppendResult(interp, " due to: ", X509_verify_cert_error_string(result), (char *) NULL);
	}
	Tcl_SetErrorCode(interp, "TLS", "HANDSHAKE", "FAILED", (char *) NULL);
	dprintf("Returning TCL_ERROR with handshake failed: %s", errStr);
	return(TCL_ERROR);
    } else {
	if (err != 0) {
	    dprintf("Got an error with a completed handshake: err = %i", err);
	}
	ret = 1;
    }

    dprintf("Returning TCL_OK with data \"%i\"", ret);
    Tcl_SetObjResult(interp, Tcl_NewIntObj(ret));
    return(TCL_OK);
	clientData = clientData;
}

static const char *command_opts [] = {
    "-alpn", "-cadir", "-cafile", "-cert", "-certfile", "-cipher", "-ciphers", "-ciphersuites",
    "-command", "-dhparams", "-key", "-keyfile", "-model", "-password", "-post_handshake",
    "-request", "-require", "-security_level", "-server", "-servername", "-session_id", "-ssl2",
    "-ssl3", "-tls1", "-tls1.1", "-tls1.2", "-tls1.3", "-validatecommand", "-vcmd", NULL};

enum _command_opts {
    _opt_alpn, _opt_cadir, _opt_cafile, _opt_cert, _opt_certfile, _opt_cipher, _opt_ciphers,
    _opt_ciphersuite, _opt_cmd, _opt_dhparams, _opt_key, _opt_keyfile, _opt_model, _opt_password,
    _opt_handshake, _opt_request, _opt_require, _opt_security_level, _opt_server, _opt_servername,
    _opt_session_id, _opt_ssl2, _opt_ssl3, _opt_tls1, _opt_tls11, _opt_tls12, _opt_tls13,
    _opt_validate, _opt_vcmd
};

/*
 *-------------------------------------------------------------------
 *
 * ImportObjCmd --
 *
 *	This procedure is invoked to process the "ssl" command
 *
 *	The ssl command pushes SSL over a (newly connected) tcp socket
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	May modify the behavior of an IO channel.
 *
 *-------------------------------------------------------------------
 */
static int
ImportObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Channel chan;		/* The channel to set a mode on. */
    State *statePtr;		/* client state for ssl socket */
    SSL_CTX *ctx	        = NULL;
    Tcl_Obj *cmdObj	        = NULL;
    Tcl_Obj *passwdObj	        = NULL;
    Tcl_Obj *vcmd	        = NULL;
    Tcl_DString upperChannelTranslation, upperChannelBlocking, upperChannelEncoding, upperChannelEOFChar;
    int idx, len, fn;
    int flags		        = TLS_TCL_INIT;
    int server		        = 0;	/* is connection incoming or outgoing? */
    char *keyfile	        = NULL;
    char *certfile	        = NULL;
    unsigned char *key  	= NULL;
    int key_len                 = 0;
    unsigned char *cert         = NULL;
    int cert_len                = 0;
    char *ciphers	        = NULL;
    char *ciphersuites	        = NULL;
    char *CAfile	        = NULL;
    char *CAdir		        = NULL;
    char *DHparams	        = NULL;
    char *model		        = NULL;
    char *servername	        = NULL;	/* hostname for Server Name Indication */
    const unsigned char *session_id = NULL;
    int sess_len                = 0;
    Tcl_Obj *alpnObj		= NULL;
    int ssl2 = 0, ssl3 = 0;
    int tls1 = 1, tls1_1 = 1, tls1_2 = 1, tls1_3 = 1;
    int proto = 0, level = -1;
    int verify = 0, require = 0, request = 1, post_handshake = 0;

    dprintf("Called");

#if defined(NO_TLS1) || defined(OPENSSL_NO_TLS1)
    tls1 = 0;
#endif
#if defined(NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1)
    tls1_1 = 0;
#endif
#if defined(NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2)
    tls1_2 = 0;
#endif
#if defined(NO_TLS1_3) || defined(OPENSSL_NO_TLS1_3)
    tls1_3 = 0;
#endif

    if (objc < 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel ?options?");
	return TCL_ERROR;
    }

    ERR_clear_error();

    chan = Tcl_GetChannel(interp, Tcl_GetStringFromObj(objv[1], NULL), NULL);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);

    for (idx = 2; idx < objc; idx++) {
	if (Tcl_GetIndexFromObj(interp, objv[idx], command_opts, "option", 0, &fn) != TCL_OK) {
	    return TCL_ERROR;
	}

	/* Validate arg has value */
	if (++idx >= objc) {
	    Tcl_AppendResult(interp, "No value for option \"", command_opts[fn], "\"", (char *) NULL);
	    return TCL_ERROR;
	}

	switch(fn) {
	case _opt_alpn:
	    alpnObj = objv[idx];
	    break;
	case _opt_cadir:
	    GET_OPT_STRING(objv[idx], CAdir, NULL);
	    break;
	case _opt_cafile:
	    GET_OPT_STRING(objv[idx], CAfile, NULL);
	    break;
	case _opt_cert:
	    GET_OPT_BYTE_ARRAY(objv[idx], cert, &cert_len);
	    break;
	case _opt_certfile:
	    GET_OPT_STRING(objv[idx], certfile, NULL);
	    break;
	case _opt_cipher:
	case _opt_ciphers:
	    GET_OPT_STRING(objv[idx], ciphers, NULL);
	    break;
	case _opt_ciphersuite:
	    GET_OPT_STRING(objv[idx], ciphersuites, NULL);
	    break;
	case _opt_cmd:
	    cmdObj = objv[idx];
	    break;
	case _opt_dhparams:
	    GET_OPT_STRING(objv[idx], DHparams, NULL);
	    break;
	case _opt_key:
	    GET_OPT_BYTE_ARRAY(objv[idx], key, &key_len);
	    break;
	case _opt_keyfile:
	    GET_OPT_STRING(objv[idx], keyfile, NULL);
	    break;
	case _opt_model:
	    GET_OPT_STRING(objv[idx], model, NULL);
	    break;
	case _opt_password:
	    passwdObj = objv[idx];
	    break;
	case _opt_handshake:
	    GET_OPT_BOOL(objv[idx], &post_handshake);
	    break;
	case _opt_request:
	    GET_OPT_BOOL(objv[idx], &request);
	    break;
	case _opt_require:
	    GET_OPT_BOOL(objv[idx], &require);
	    break;
	case _opt_security_level:
	    GET_OPT_INT(objv[idx], &level);
	    break;
	case _opt_server:
	    GET_OPT_BOOL(objv[idx], &server);
	    break;
	case _opt_servername:
	    GET_OPT_STRING(objv[idx], servername, NULL);
	    break;
	case _opt_session_id:
	    GET_OPT_BYTE_ARRAY(objv[idx], session_id, &sess_len);
	    break;
	case _opt_ssl2:
	    GET_OPT_INT(objv[idx], &ssl2);
	    break;
	case _opt_ssl3:
	    GET_OPT_INT(objv[idx], &ssl3);
	    break;
	case _opt_tls1:
	    GET_OPT_INT(objv[idx], &tls1);
	    break;
	case _opt_tls11:
	    GET_OPT_INT(objv[idx], &tls1_1);
	    break;
	case _opt_tls12:
	    GET_OPT_INT(objv[idx], &tls1_2);
	    break;
	case _opt_tls13:
	    GET_OPT_INT(objv[idx], &tls1_3);
	    break;
	case _opt_validate:
	case _opt_vcmd:
	    vcmd = objv[idx];
	    break;
	}
    }

    if (request)		verify |= SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_PEER;
    if (request && require)	verify |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    if (request && post_handshake)	verify |= SSL_VERIFY_POST_HANDSHAKE;
    if (verify == 0)		verify = SSL_VERIFY_NONE;

    proto |= (ssl2 ? TLS_PROTO_SSL2 : 0);
    proto |= (ssl3 ? TLS_PROTO_SSL3 : 0);
    proto |= (tls1 ? TLS_PROTO_TLS1 : 0);
    proto |= (tls1_1 ? TLS_PROTO_TLS1_1 : 0);
    proto |= (tls1_2 ? TLS_PROTO_TLS1_2 : 0);
    proto |= (tls1_3 ? TLS_PROTO_TLS1_3 : 0);

    /* reset to NULL if blank string provided */
    if (cert && !*cert)		        cert	        = NULL;
    if (key && !*key)		        key	        = NULL;
    if (certfile && !*certfile)         certfile	= NULL;
    if (keyfile && !*keyfile)		keyfile	        = NULL;
    if (ciphers && !*ciphers)	        ciphers	        = NULL;
    if (ciphersuites && !*ciphersuites) ciphersuites    = NULL;
    if (CAfile && !*CAfile)	        CAfile	        = NULL;
    if (CAdir && !*CAdir)	        CAdir	        = NULL;
    if (DHparams && !*DHparams)	        DHparams        = NULL;

    /* new SSL state */
    statePtr		= (State *) ckalloc((unsigned) sizeof(State));
    memset(statePtr, 0, sizeof(State));

    statePtr->flags	= flags;
    statePtr->interp	= interp;
    statePtr->vflags	= verify;
    statePtr->err	= "";

    /* allocate script */
    if (cmdObj != NULL) {
	(void) Tcl_GetStringFromObj(cmdObj, &len);
	if (len) {
	    statePtr->callback = cmdObj;
	    Tcl_IncrRefCount(statePtr->callback);
	}
    }

    /* allocate password */
    if (passwdObj != NULL) {
	(void) Tcl_GetStringFromObj(passwdObj, &len);
	if (len) {
	    statePtr->password = passwdObj;
	    Tcl_IncrRefCount(statePtr->password);
	}
    }

    /* allocate validate command */
    if (vcmd) {
	(void) Tcl_GetStringFromObj(vcmd, &len);
	if (len) {
	    statePtr->vcmd = vcmd;
	    Tcl_IncrRefCount(statePtr->vcmd);
	}
    }

    if (model != NULL) {
	int mode;
	/* Get the "model" context */
	chan = Tcl_GetChannel(interp, model, &mode);
	if (chan == (Tcl_Channel) NULL) {
	    Tls_Free((char *) statePtr);
	    return TCL_ERROR;
	}

	/*
	 * Make sure to operate on the topmost channel
	 */
	chan = Tcl_GetTopChannel(chan);
	if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	    Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
		"\": not a TLS channel", NULL);
	    Tcl_SetErrorCode(interp, "TLS", "IMPORT", "CHANNEL", "INVALID", (char *) NULL);
	    Tls_Free((char *) statePtr);
	    return TCL_ERROR;
	}
	ctx = ((State *)Tcl_GetChannelInstanceData(chan))->ctx;
    } else {
	if ((ctx = CTX_Init(statePtr, server, proto, keyfile, certfile, key, cert, key_len,
	    cert_len, CAdir, CAfile, ciphers, ciphersuites, level, DHparams)) == NULL) {
	    Tls_Free((char *) statePtr);
	    return TCL_ERROR;
	}
    }

    statePtr->ctx = ctx;

    /*
     * We need to make sure that the channel works in binary (for the
     * encryption not to get goofed up).
     * We only want to adjust the buffering in pre-v2 channels, where
     * each channel in the stack maintained its own buffers.
     */
    Tcl_DStringInit(&upperChannelTranslation);
    Tcl_DStringInit(&upperChannelBlocking);
    Tcl_DStringInit(&upperChannelEOFChar);
    Tcl_DStringInit(&upperChannelEncoding);
    Tcl_GetChannelOption(interp, chan, "-eofchar", &upperChannelEOFChar);
    Tcl_GetChannelOption(interp, chan, "-encoding", &upperChannelEncoding);
    Tcl_GetChannelOption(interp, chan, "-translation", &upperChannelTranslation);
    Tcl_GetChannelOption(interp, chan, "-blocking", &upperChannelBlocking);
    Tcl_SetChannelOption(interp, chan, "-translation", "binary");
    Tcl_SetChannelOption(interp, chan, "-blocking", "true");
    dprintf("Consuming Tcl channel %s", Tcl_GetChannelName(chan));
    statePtr->self = Tcl_StackChannel(interp, Tls_ChannelType(), (ClientData) statePtr, (TCL_READABLE | TCL_WRITABLE), chan);
    dprintf("Created channel named %s", Tcl_GetChannelName(statePtr->self));
    if (statePtr->self == (Tcl_Channel) NULL) {
	/*
	 * No use of Tcl_EventuallyFree because no possible Tcl_Preserve.
	 */
	Tls_Free((char *) statePtr);
	return TCL_ERROR;
    }

    Tcl_SetChannelOption(interp, statePtr->self, "-translation", Tcl_DStringValue(&upperChannelTranslation));
    Tcl_SetChannelOption(interp, statePtr->self, "-encoding", Tcl_DStringValue(&upperChannelEncoding));
    Tcl_SetChannelOption(interp, statePtr->self, "-eofchar", Tcl_DStringValue(&upperChannelEOFChar));
    Tcl_SetChannelOption(interp, statePtr->self, "-blocking", Tcl_DStringValue(&upperChannelBlocking));

    /*
     * SSL Initialization
     */
    statePtr->ssl = SSL_new(statePtr->ctx);
    if (!statePtr->ssl) {
	/* SSL library error */
	Tcl_AppendResult(interp, "couldn't construct ssl session: ", REASON(), (char *) NULL);
	    Tcl_SetErrorCode(interp, "TLS", "IMPORT", "INIT", "FAILED", (char *) NULL);
	Tls_Free((char *) statePtr);
	return TCL_ERROR;
    }

    /* Set host server name */
    if (servername) {
	/* Sets the server name indication (SNI) in ClientHello extension */
	/* Per RFC 6066, hostname is a ASCII encoded string, though RFC 4366 says UTF-8. */
	if (!SSL_set_tlsext_host_name(statePtr->ssl, servername) && require) {
	    Tcl_AppendResult(interp, "setting TLS host name extension failed", (char *) NULL);
	    Tcl_SetErrorCode(interp, "TLS", "IMPORT", "SNI", "FAILED", (char *) NULL);
	    Tls_Free((char *) statePtr);
	    return TCL_ERROR;
	}

	/* Set hostname for peer certificate hostname verification in clients.
	   Don't use SSL_set1_host since it has limitations. */
	if (!SSL_add1_host(statePtr->ssl, servername)) {
	    Tcl_AppendResult(interp, "setting DNS host name failed", (char *) NULL);
	    Tcl_SetErrorCode(interp, "TLS", "IMPORT", "HOSTNAME", "FAILED", (char *) NULL);
	    Tls_Free((char *) statePtr);
	    return TCL_ERROR;
	}
    }

    /* Resume session id */
    if (session_id && sess_len <= SSL_MAX_SID_CTX_LENGTH) {
	/* SSL_set_session() */
	if (!SSL_SESSION_set1_id_context(SSL_get_session(statePtr->ssl), session_id, (unsigned int) sess_len)) {
	    Tcl_AppendResult(interp, "Resume session id ", session_id, " failed", (char *) NULL);
	    Tcl_SetErrorCode(interp, "TLS", "IMPORT", "SESSION", "FAILED", (char *) NULL);
	    Tls_Free((char *) statePtr);
	    return TCL_ERROR;
	}
    }

    /* Enable Application-Layer Protocol Negotiation. Examples are: http/1.0,
	http/1.1, h2, h3, ftp, imap, pop3, xmpp-client, xmpp-server, mqtt, irc, etc. */
    if (alpnObj != NULL) {
	/* Convert a TCL list into a protocol-list in wire-format */
	unsigned char *protos, *p;
	unsigned int protos_len = 0;
	int i, len, cnt;
	Tcl_Obj **list;

	if (Tcl_ListObjGetElements(interp, alpnObj, &cnt, &list) != TCL_OK) {
	    Tls_Free((char *) statePtr);
	    return TCL_ERROR;
	}

	/* Determine the memory required for the protocol-list */
	for (i = 0; i < cnt; i++) {
	    Tcl_GetStringFromObj(list[i], &len);
	    if (len > 255) {
		Tcl_AppendResult(interp, "ALPN protocol name too long", (char *) NULL);
		Tcl_SetErrorCode(interp, "TLS", "IMPORT", "ALPN", "FAILED", (char *) NULL);
		Tls_Free((char *) statePtr);
		return TCL_ERROR;
	    }
	    protos_len += 1 + len;
	}

	/* Build the complete protocol-list */
	protos = ckalloc(protos_len);
	/* protocol-lists consist of 8-bit length-prefixed, byte strings */
	for (i = 0, p = protos; i < cnt; i++) {
	    char *str = Tcl_GetStringFromObj(list[i], &len);
	    *p++ = len;
	    memcpy(p, str, len);
	    p += len;
	}

	/* SSL_set_alpn_protos makes a copy of the protocol-list */
	/* Note: This functions reverses the return value convention */
	if (SSL_set_alpn_protos(statePtr->ssl, protos, protos_len)) {
	    Tcl_AppendResult(interp, "failed to set ALPN protocols", (char *) NULL);
	    Tcl_SetErrorCode(interp, "TLS", "IMPORT", "ALPN", "FAILED", (char *) NULL);
	    Tls_Free((char *) statePtr);
	    ckfree(protos);
	    return TCL_ERROR;
	}

	/* Store protocols list */
	statePtr->protos = protos;
	statePtr->protos_len = protos_len;
    } else {
	statePtr->protos = NULL;
	statePtr->protos_len = 0;
    }

    /*
     * SSL Callbacks
     */
    SSL_set_app_data(statePtr->ssl, (void *)statePtr);	/* point back to us */

    SSL_set_verify(statePtr->ssl, verify, VerifyCallback);
    SSL_set_info_callback(statePtr->ssl, InfoCallback);

    /* Callback for observing protocol messages */
#ifndef OPENSSL_NO_SSL_TRACE
    /* void SSL_CTX_set_msg_callback_arg(statePtr->ctx, (void *)statePtr);
    void SSL_CTX_set_msg_callback(statePtr->ctx, MessageCallback); */
    SSL_set_msg_callback_arg(statePtr->ssl, (void *)statePtr);
    SSL_set_msg_callback(statePtr->ssl, MessageCallback);
#endif

    /* Create Tcl_Channel BIO Handler */
    statePtr->p_bio	= BIO_new_tcl(statePtr, BIO_NOCLOSE);
    statePtr->bio	= BIO_new(BIO_f_ssl());

    if (server) {
	/* Server callbacks */
	SSL_CTX_set_tlsext_servername_arg(statePtr->ctx, (void *)statePtr);
	SSL_CTX_set_tlsext_servername_callback(statePtr->ctx, SNICallback);
	SSL_CTX_set_client_hello_cb(statePtr->ctx, HelloCallback, (void *)statePtr);
	if (statePtr->protos != NULL) {
	    SSL_CTX_set_alpn_select_cb(statePtr->ctx, ALPNCallback, (void *)statePtr);
#ifdef USE_NPN
	    if (tls1_2 == 0 && tls1_3 == 0) {
		SSL_CTX_set_next_protos_advertised_cb(statePtr->ctx, NPNCallback, (void *)statePtr);
	    }
#endif
	}

	/* Enable server to send cert request after handshake (TLS 1.3 only) */
	/* A write operation must take place for the Certificate Request to be
	   sent to the client, this can be done with SSL_do_handshake(). */
	if (request && post_handshake && tls1_3) {
	    SSL_verify_client_post_handshake(statePtr->ssl);
	}

	/* set automatic curve selection */
	SSL_set_ecdh_auto(statePtr->ssl, 1);

	/* Set server mode */
	statePtr->flags |= TLS_TCL_SERVER;
	SSL_set_accept_state(statePtr->ssl);
    } else {
	/* Client callbacks */
#ifdef USE_NPN
	if (statePtr->protos != NULL && tls1_2 == 0 && tls1_3 == 0) {
	    SSL_CTX_set_next_proto_select_cb(statePtr->ctx, ALPNCallback, (void *)statePtr);
	}
#endif

	/* Session caching */
	SSL_CTX_set_session_cache_mode(statePtr->ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
	SSL_CTX_sess_set_new_cb(statePtr->ctx, SessionCallback);

	/* Enable post handshake Authentication extension. TLS 1.3 only, not http/2. */
	if (request && post_handshake) {
	    SSL_set_post_handshake_auth(statePtr->ssl, 1);
	}

	/* Set client mode */
	SSL_set_connect_state(statePtr->ssl);
    }
    SSL_set_bio(statePtr->ssl, statePtr->p_bio, statePtr->p_bio);
    BIO_set_ssl(statePtr->bio, statePtr->ssl, BIO_NOCLOSE);

    /*
     * End of SSL Init
     */
    dprintf("Returning %s", Tcl_GetChannelName(statePtr->self));
    Tcl_SetResult(interp, (char *) Tcl_GetChannelName(statePtr->self), TCL_VOLATILE);

    return TCL_OK;
	clientData = clientData;
}

/*
 *-------------------------------------------------------------------
 *
 * UnimportObjCmd --
 *
 *	This procedure is invoked to remove the topmost channel filter.
 *
 * Results:
 *	A standard Tcl result.
 *
 * Side effects:
 *	May modify the behavior of an IO channel.
 *
 *-------------------------------------------------------------------
 */
static int
UnimportObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Channel chan;		/* The channel to set a mode on. */

    dprintf("Called");

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return TCL_ERROR;
    }

    chan = Tcl_GetChannel(interp, Tcl_GetString(objv[1]), NULL);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);

    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
		"\": not a TLS channel", NULL);
	    Tcl_SetErrorCode(interp, "TLS", "UNIMPORT", "CHANNEL", "INVALID", (char *) NULL);
	return TCL_ERROR;
    }

    if (Tcl_UnstackChannel(interp, chan) == TCL_ERROR) {
	return TCL_ERROR;
    }

    return TCL_OK;
	clientData = clientData;
}

/*
 *-------------------------------------------------------------------
 *
 * CTX_Init -- construct a SSL_CTX instance
 *
 * Results:
 *	A valid SSL_CTX instance or NULL.
 *
 * Side effects:
 *	constructs SSL context (CTX)
 *
 *-------------------------------------------------------------------
 */
static SSL_CTX *
CTX_Init(State *statePtr, int isServer, int proto, char *keyfile, char *certfile,
    unsigned char *key, unsigned char *cert, int key_len, int cert_len, char *CAdir,
    char *CAfile, char *ciphers, char *ciphersuites, int level, char *DHparams) {
    Tcl_Interp *interp = statePtr->interp;
    SSL_CTX *ctx = NULL;
    Tcl_DString ds;
    Tcl_DString ds1;
    int off = 0;
    int load_private_key;
    const SSL_METHOD *method;

    dprintf("Called");

    if (!proto) {
	Tcl_AppendResult(interp, "no valid protocol selected", NULL);
	return NULL;
    }

    /* create SSL context */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L || defined(NO_SSL2) || defined(OPENSSL_NO_SSL2)
    if (ENABLED(proto, TLS_PROTO_SSL2)) {
	Tcl_AppendResult(interp, "SSL2 protocol not supported", NULL);
	return NULL;
    }
#endif
#if defined(NO_SSL3) || defined(OPENSSL_NO_SSL3)
    if (ENABLED(proto, TLS_PROTO_SSL3)) {
	Tcl_AppendResult(interp, "SSL3 protocol not supported", NULL);
	return NULL;
    }
#endif
#if defined(NO_TLS1) || defined(OPENSSL_NO_TLS1)
    if (ENABLED(proto, TLS_PROTO_TLS1)) {
	Tcl_AppendResult(interp, "TLS 1.0 protocol not supported", NULL);
	return NULL;
    }
#endif
#if defined(NO_TLS1_1) || defined(OPENSSL_NO_TLS1_1)
    if (ENABLED(proto, TLS_PROTO_TLS1_1)) {
	Tcl_AppendResult(interp, "TLS 1.1 protocol not supported", NULL);
	return NULL;
    }
#endif
#if defined(NO_TLS1_2) || defined(OPENSSL_NO_TLS1_2)
    if (ENABLED(proto, TLS_PROTO_TLS1_2)) {
	Tcl_AppendResult(interp, "TLS 1.2 protocol not supported", NULL);
	return NULL;
    }
#endif
#if defined(NO_TLS1_3) || defined(OPENSSL_NO_TLS1_3)
    if (ENABLED(proto, TLS_PROTO_TLS1_3)) {
	Tcl_AppendResult(interp, "TLS 1.3 protocol not supported", NULL);
	return NULL;
    }
#endif
    if (proto == 0) {
	/* Use full range */
	SSL_CTX_set_min_proto_version(ctx, 0);
	SSL_CTX_set_max_proto_version(ctx, 0);
    }

    switch (proto) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(NO_SSL2) && !defined(OPENSSL_NO_SSL2)
    case TLS_PROTO_SSL2:
	method = isServer ? SSLv2_server_method() : SSLv2_client_method();
	break;
#endif
#if !defined(NO_SSL3) && !defined(OPENSSL_NO_SSL3) && !defined(OPENSSL_NO_SSL3_METHOD)
    case TLS_PROTO_SSL3:
	method = isServer ? SSLv3_server_method() : SSLv3_client_method();
	break;
#endif
#if !defined(NO_TLS1) && !defined(OPENSSL_NO_TLS1) && !defined(OPENSSL_NO_TLS1_METHOD)
    case TLS_PROTO_TLS1:
	method = isServer ? TLSv1_server_method() : TLSv1_client_method();
	break;
#endif
#if !defined(NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1_METHOD)
    case TLS_PROTO_TLS1_1:
	method = isServer ? TLSv1_1_server_method() : TLSv1_1_client_method();
	break;
#endif
#if !defined(NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2_METHOD)
    case TLS_PROTO_TLS1_2:
	method = isServer ? TLSv1_2_server_method() : TLSv1_2_client_method();
	break;
#endif
#if !defined(NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3)
    case TLS_PROTO_TLS1_3:
	/* Use the generic method and constraint range after context is created */
	method = isServer ? TLS_server_method() : TLS_client_method();
	break;
#endif
    default:
	/* Negotiate highest available SSL/TLS version */
	method = isServer ? TLS_server_method() : TLS_client_method();
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(NO_SSL2) && !defined(OPENSSL_NO_SSL2)
	off |= (ENABLED(proto, TLS_PROTO_SSL2)   ? 0 : SSL_OP_NO_SSLv2);
#endif
#if !defined(NO_SSL3) && !defined(OPENSSL_NO_SSL3)
	off |= (ENABLED(proto, TLS_PROTO_SSL3)   ? 0 : SSL_OP_NO_SSLv3);
#endif
#if !defined(NO_TLS1) && !defined(OPENSSL_NO_TLS1)
	off |= (ENABLED(proto, TLS_PROTO_TLS1)   ? 0 : SSL_OP_NO_TLSv1);
#endif
#if !defined(NO_TLS1_1) && !defined(OPENSSL_NO_TLS1_1)
	off |= (ENABLED(proto, TLS_PROTO_TLS1_1) ? 0 : SSL_OP_NO_TLSv1_1);
#endif
#if !defined(NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_2)
	off |= (ENABLED(proto, TLS_PROTO_TLS1_2) ? 0 : SSL_OP_NO_TLSv1_2);
#endif
#if !defined(NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3)
	off |= (ENABLED(proto, TLS_PROTO_TLS1_3) ? 0 : SSL_OP_NO_TLSv1_3);
#endif
	break;
    }

    ERR_clear_error();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	return(NULL);
    }

    if (getenv(SSLKEYLOGFILE)) {
	SSL_CTX_set_keylog_callback(ctx, KeyLogCallback);
    }

#if !defined(NO_TLS1_3) && !defined(OPENSSL_NO_TLS1_3)
    if (proto == TLS_PROTO_TLS1_3) {
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    }
#endif

    /* Force cipher selection order by server */
    if (!isServer) {
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms(); /* Load ciphers and digests */
#endif

    SSL_CTX_set_app_data(ctx, (void*)interp);	/* remember the interpreter */
    SSL_CTX_set_options(ctx, SSL_OP_ALL);	/* all SSL bug workarounds */
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);	/* disable compression even if supported */
    SSL_CTX_set_options(ctx, off);		/* disable protocol versions */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);	/* handle new handshakes in background. On by default in OpenSSL 1.1.1. */
#endif
    SSL_CTX_sess_set_cache_size(ctx, 128);

    /* Set user defined ciphers, cipher suites, and security level */
    if ((ciphers != NULL) && !SSL_CTX_set_cipher_list(ctx, ciphers)) {
	Tcl_AppendResult(interp, "Set ciphers failed: No valid ciphers", (char *) NULL);
	SSL_CTX_free(ctx);
	return NULL;
    }
    if ((ciphersuites != NULL) && !SSL_CTX_set_ciphersuites(ctx, ciphersuites)) {
	Tcl_AppendResult(interp, "Set cipher suites failed: No valid ciphers", (char *) NULL);
	SSL_CTX_free(ctx);
	return NULL;
    }

    /* Set security level */
    if (level > -1 && level < 6) {
	/* SSL_set_security_level */
	SSL_CTX_set_security_level(ctx, level);
    }

    /* set some callbacks */
    SSL_CTX_set_default_passwd_cb(ctx, PasswordCallback);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)statePtr);

    /* read a Diffie-Hellman parameters file, or use the built-in one */
#ifdef OPENSSL_NO_DH
    if (DHparams != NULL) {
	Tcl_AppendResult(interp, "DH parameter support not available", (char *) NULL);
	SSL_CTX_free(ctx);
	return NULL;
    }
#else
    {
	DH* dh;
	if (DHparams != NULL) {
	    BIO *bio;
	    Tcl_DStringInit(&ds);
	    bio = BIO_new_file(F2N(DHparams, &ds), "r");
	    if (!bio) {
		Tcl_DStringFree(&ds);
		Tcl_AppendResult(interp, "Could not find DH parameters file", (char *) NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }

	    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	    BIO_free(bio);
	    Tcl_DStringFree(&ds);
	    if (!dh) {
		Tcl_AppendResult(interp, "Could not read DH parameters from file", (char *) NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }
	} else {
	    dh = get_dhParams();
	}
	SSL_CTX_set_tmp_dh(ctx, dh);
	DH_free(dh);
    }
#endif

    /* set our certificate */
    load_private_key = 0;
    if (certfile != NULL) {
	load_private_key = 1;

	Tcl_DStringInit(&ds);

	if (SSL_CTX_use_certificate_file(ctx, F2N(certfile, &ds), SSL_FILETYPE_PEM) <= 0) {
	    Tcl_DStringFree(&ds);
	    Tcl_AppendResult(interp, "unable to set certificate file ", certfile, ": ",
			     REASON(), (char *) NULL);
	    SSL_CTX_free(ctx);
	    return NULL;
	}
    } else if (cert != NULL) {
	load_private_key = 1;
	if (SSL_CTX_use_certificate_ASN1(ctx, cert_len, cert) <= 0) {
	    Tcl_DStringFree(&ds);
	    Tcl_AppendResult(interp, "unable to set certificate: ",
			     REASON(), (char *) NULL);
	    SSL_CTX_free(ctx);
	    return NULL;
	}
    } else {
	certfile = (char*)X509_get_default_cert_file();

	if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) <= 0) {
#if 0
	    Tcl_DStringFree(&ds);
	    Tcl_AppendResult(interp, "unable to use default certificate file ", certfile, ": ",
			     REASON(), (char *) NULL);
	    SSL_CTX_free(ctx);
	    return NULL;
#endif
	}
    }

    /* set our private key */
    if (load_private_key) {
	if (keyfile == NULL && key == NULL) {
	    keyfile = certfile;
	}

	if (keyfile != NULL) {
	    /* get the private key associated with this certificate */
	    if (keyfile == NULL) {
		keyfile = certfile;
	    }

	    if (SSL_CTX_use_PrivateKey_file(ctx, F2N(keyfile, &ds), SSL_FILETYPE_PEM) <= 0) {
		Tcl_DStringFree(&ds);
		/* flush the passphrase which might be left in the result */
		Tcl_SetResult(interp, NULL, TCL_STATIC);
		Tcl_AppendResult(interp, "unable to set public key file ", keyfile, " ",
			         REASON(), (char *) NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }
	    Tcl_DStringFree(&ds);

	} else if (key != NULL) {
	    if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx, key,key_len) <= 0) {
		Tcl_DStringFree(&ds);
		/* flush the passphrase which might be left in the result */
		Tcl_SetResult(interp, NULL, TCL_STATIC);
		Tcl_AppendResult(interp, "unable to set public key: ", REASON(), (char *) NULL);
		SSL_CTX_free(ctx);
		return NULL;
	    }
	}
	/* Now we know that a key and cert have been set against
	 * the SSL context */
	if (!SSL_CTX_check_private_key(ctx)) {
	    Tcl_AppendResult(interp, "private key does not match the certificate public key",
			     (char *) NULL);
	    SSL_CTX_free(ctx);
	    return NULL;
	}
    }

    /* Set verification CAs */
    Tcl_DStringInit(&ds);
    Tcl_DStringInit(&ds1);
    /* There is one default directory, one default file, and one default store.
	The default CA certificates directory (and default store) is in the OpenSSL
	certs directory. It can be overridden by the SSL_CERT_DIR env var. The
	default CA certificates file is called cert.pem in the default OpenSSL
	directory. It can be overridden by the SSL_CERT_FILE env var. */
	/* int SSL_CTX_set_default_verify_dir(SSL_CTX *ctx) and int SSL_CTX_set_default_verify_file(SSL_CTX *ctx) */
    if (!SSL_CTX_load_verify_locations(ctx, F2N(CAfile, &ds), F2N(CAdir, &ds1)) ||
	!SSL_CTX_set_default_verify_paths(ctx)) {
#if 0
	Tcl_DStringFree(&ds);
	Tcl_DStringFree(&ds1);
	/* Don't currently care if this fails */
	Tcl_AppendResult(interp, "SSL default verify paths: ", REASON(), (char *) NULL);
	SSL_CTX_free(ctx);
	return NULL;
#endif
    }

    /* https://sourceforge.net/p/tls/bugs/57/ */
    /* XXX:TODO: Let the user supply values here instead of something that exists on the filesystem */
    if (CAfile != NULL) {
	STACK_OF(X509_NAME) *certNames = SSL_load_client_CA_file(F2N(CAfile, &ds));
	if (certNames != NULL) {
	    SSL_CTX_set_client_CA_list(ctx, certNames);
	}
    }

    Tcl_DStringFree(&ds);
    Tcl_DStringFree(&ds1);
    return ctx;
}

/*
 *-------------------------------------------------------------------
 *
 * StatusObjCmd -- return certificate for connected peer.
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
StatusObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    State *statePtr;
    X509 *peer;
    Tcl_Obj *objPtr;
    Tcl_Channel chan;
    char *channelName, *ciphers;
    int mode;
    const unsigned char *proto;
    unsigned int len;
    int nid, res;

    dprintf("Called");

    if (objc < 2 || objc > 3 || (objc == 3 && !strcmp(Tcl_GetString(objv[1]), "-local"))) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-local? channel");
	return TCL_ERROR;
    }

    /* Get channel Id */
    channelName = Tcl_GetStringFromObj(objv[(objc == 2 ? 1 : 2)], NULL);
    chan = Tcl_GetChannel(interp, channelName, &mode);
    if (chan == (Tcl_Channel) NULL) {
	return TCL_ERROR;
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
		"\": not a TLS channel", NULL);
	Tcl_SetErrorCode(interp, "TLS", "STATUS", "CHANNEL", "INVALID", (char *) NULL);
	return TCL_ERROR;
    }
    statePtr = (State *) Tcl_GetChannelInstanceData(chan);

    /* Get certificate for peer or self */
    if (objc == 2) {
	peer = SSL_get_peer_certificate(statePtr->ssl);
    } else {
	peer = SSL_get_certificate(statePtr->ssl);
    }

    /* Get X509 certificate info */
    if (peer) {
	objPtr = Tls_NewX509Obj(interp, peer);
	if (objc == 2) {
	    X509_free(peer);
	    peer = NULL;
	}
    } else {
	objPtr = Tcl_NewListObj(0, NULL);
    }

    /* Peer name */
    LAPPEND_STR(interp, objPtr, "peername", SSL_get0_peername(statePtr->ssl), -1);
    LAPPEND_INT(interp, objPtr, "sbits", SSL_get_cipher_bits(statePtr->ssl, NULL));

    ciphers = (char*)SSL_get_cipher(statePtr->ssl);
    LAPPEND_STR(interp, objPtr, "cipher", ciphers, -1);

    /* Verify the X509 certificate presented by the peer */
    LAPPEND_STR(interp, objPtr, "verifyResult",
	X509_verify_cert_error_string(SSL_get_verify_result(statePtr->ssl)), -1);

    /* Verify mode */
    mode = SSL_get_verify_mode(statePtr->ssl);
    if (mode && SSL_VERIFY_NONE) {
	LAPPEND_STR(interp, objPtr, "verifyMode", "none", -1);
    } else {
	Tcl_Obj *listObjPtr = Tcl_NewListObj(0, NULL);
	if (mode && SSL_VERIFY_PEER) {
	    Tcl_ListObjAppendElement(interp, listObjPtr, Tcl_NewStringObj("peer", -1));
	}
	if (mode && SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
	    Tcl_ListObjAppendElement(interp, listObjPtr, Tcl_NewStringObj("fail if no peer cert", -1));
	}
	if (mode && SSL_VERIFY_CLIENT_ONCE) {
	    Tcl_ListObjAppendElement(interp, listObjPtr, Tcl_NewStringObj("client once", -1));
	}
	if (mode && SSL_VERIFY_POST_HANDSHAKE) {
	    Tcl_ListObjAppendElement(interp, listObjPtr, Tcl_NewStringObj("post handshake", -1));
	}
	LAPPEND_OBJ(interp, objPtr, "verifyMode", listObjPtr)
    }

    /* Verify mode depth */
    LAPPEND_INT(interp, objPtr, "verifyDepth", SSL_get_verify_depth(statePtr->ssl));

    /* Report the selected protocol as a result of the negotiation */
    SSL_get0_alpn_selected(statePtr->ssl, &proto, &len);
    LAPPEND_STR(interp, objPtr, "alpn", (char *)proto, (int) len);
    LAPPEND_STR(interp, objPtr, "protocol", SSL_get_version(statePtr->ssl), -1);

    /* Valid for non-RSA signature and TLS 1.3 */
    if (objc == 2) {
	res = SSL_get_peer_signature_nid(statePtr->ssl, &nid);
    } else {
	res = SSL_get_signature_nid(statePtr->ssl, &nid);
    }
    if (!res) {nid = 0;}
    LAPPEND_STR(interp, objPtr, "signatureHashAlgorithm", OBJ_nid2ln(nid), -1);

    if (objc == 2) {
	res = SSL_get_peer_signature_type_nid(statePtr->ssl, &nid);
    } else {
	res = SSL_get_signature_type_nid(statePtr->ssl, &nid);
    }
    if (!res) {nid = 0;}
    LAPPEND_STR(interp, objPtr, "signatureType", OBJ_nid2ln(nid), -1);

    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
	clientData = clientData;
}

/*
 *-------------------------------------------------------------------
 *
 * ConnectionInfoObjCmd -- return connection info from OpenSSL.
 *
 * Results:
 *	A list of connection info
  *
 *-------------------------------------------------------------------
 */

static int ConnectionInfoObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Channel chan;		/* The channel to set a mode on */
    State *statePtr;		/* client state for ssl socket */
    Tcl_Obj *objPtr, *listPtr;
    const SSL *ssl;
    const SSL_CIPHER *cipher;
    const SSL_SESSION *session;
    const EVP_MD *md;

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return(TCL_ERROR);
    }

    chan = Tcl_GetChannel(interp, Tcl_GetStringFromObj(objv[1], NULL), NULL);
    if (chan == (Tcl_Channel) NULL) {
	return(TCL_ERROR);
    }

    /* Make sure to operate on the topmost channel */
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != Tls_ChannelType()) {
	Tcl_AppendResult(interp, "bad channel \"", Tcl_GetChannelName(chan),
	    "\": not a TLS channel", NULL);
	Tcl_SetErrorCode(interp, "TLS", "CONNECTION", "CHANNEL", "INVALID", (char *) NULL);
	return(TCL_ERROR);
    }

    objPtr = Tcl_NewListObj(0, NULL);

    /* Connection info */
    statePtr = (State *)Tcl_GetChannelInstanceData(chan);
    ssl = statePtr->ssl;
    if (ssl != NULL) {
	/* connection state */
	LAPPEND_STR(interp, objPtr, "state", SSL_state_string_long(ssl), -1);

	/* Get SNI requested server name */
	LAPPEND_STR(interp, objPtr, "servername", SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name), -1);

	/* Get protocol */
	LAPPEND_STR(interp, objPtr, "protocol", SSL_get_version(ssl), -1);

	/* Renegotiation allowed */
	LAPPEND_BOOL(interp, objPtr, "renegotiation_allowed", SSL_get_secure_renegotiation_support(ssl));

	/* Get security level */
	LAPPEND_INT(interp, objPtr, "security_level", SSL_get_security_level(ssl));

	/* Session info */
	LAPPEND_BOOL(interp, objPtr, "session_reused", SSL_session_reused(ssl));

	/* Is server info */
	LAPPEND_BOOL(interp, objPtr, "is_server", SSL_is_server(ssl));

	/* Is DTLS */
	LAPPEND_BOOL(interp, objPtr, "is_dtls", SSL_is_dtls(ssl));
    }

    /* Cipher info */
    cipher = SSL_get_current_cipher(ssl);
    if (cipher != NULL) {
	char buf[BUFSIZ] = {0};
	int bits, alg_bits;

	/* Cipher name */
	LAPPEND_STR(interp, objPtr, "cipher", SSL_CIPHER_get_name(cipher), -1);

	/* RFC name of cipher */
	LAPPEND_STR(interp, objPtr, "standard_name", SSL_CIPHER_standard_name(cipher), -1);

	/* OpenSSL name of cipher */
	LAPPEND_STR(interp, objPtr, "openssl_name", OPENSSL_cipher_name(SSL_CIPHER_standard_name(cipher)), -1);

	/* number of secret bits used for cipher */
	bits = SSL_CIPHER_get_bits(cipher, &alg_bits);
	LAPPEND_INT(interp, objPtr, "secret_bits", bits);
	LAPPEND_INT(interp, objPtr, "algorithm_bits", alg_bits);
	/* alg_bits is actual key secret bits. If use bits and secret (algorithm) bits differ,
	   the rest of the bits are fixed, i.e. for limited export ciphers (bits < 56) */

	/* Indicates which SSL/TLS protocol version first defined the cipher */
	LAPPEND_STR(interp, objPtr, "min_version", SSL_CIPHER_get_version(cipher), -1);

	/* Cipher NID, digest NID (none for AEAD cipher suites), Key Exchange NID, and authentication NID */
	LAPPEND_STR(interp, objPtr, "cipherNID", (char *)OBJ_nid2ln(SSL_CIPHER_get_cipher_nid(cipher)), -1);
	LAPPEND_STR(interp, objPtr, "digestNID", (char *)OBJ_nid2ln(SSL_CIPHER_get_digest_nid(cipher)), -1);
	LAPPEND_STR(interp, objPtr, "keyExchangeNID", (char *)OBJ_nid2ln(SSL_CIPHER_get_kx_nid(cipher)), -1);
	LAPPEND_STR(interp, objPtr, "authenticationNID", (char *)OBJ_nid2ln(SSL_CIPHER_get_auth_nid(cipher)), -1);

	/* message authentication code - Cipher is AEAD (e.g. GCM or ChaCha20/Poly1305) or not */
	/* Authenticated Encryption with associated data (AEAD) check */
	LAPPEND_BOOL(interp, objPtr, "cipher_is_aead", SSL_CIPHER_is_aead(cipher));

	/* Get OpenSSL-specific ID, not IANA ID */
	LAPPEND_INT(interp, objPtr, "cipher_id", (int) SSL_CIPHER_get_id(cipher));

	/* Two-byte ID used in the TLS protocol of the given cipher */
	LAPPEND_INT(interp, objPtr, "protocol_id", (int) SSL_CIPHER_get_protocol_id(cipher));

	/* Textual description of the cipher. Includes: cipher name, protocol version, key
	   exchange, authentication, symmetric encryption method, message authentication code */
	if (SSL_CIPHER_description(cipher, buf, sizeof(buf)) != NULL) {
	    LAPPEND_STR(interp, objPtr, "description", buf, -1);
	}

	/* Digest used during the SSL/TLS handshake when using the cipher. */
	md = SSL_CIPHER_get_handshake_digest(cipher);
	LAPPEND_STR(interp, objPtr, "handshake_digest", (char *)EVP_MD_name(md), -1);
    }

    /* Session info */
    session = SSL_get_session(ssl);
    if (session != NULL) {
	const unsigned char *ticket;
	size_t len2;
	unsigned int ulen;
	const unsigned char *session_id, *proto;
	char buffer[SSL_MAX_MASTER_KEY_LENGTH];

	/* Report the selected protocol as a result of the ALPN negotiation */
	SSL_SESSION_get0_alpn_selected(session, &proto, &len2);
	LAPPEND_STR(interp, objPtr, "alpn", (char *) proto, (int) len2);

	/* Report the selected protocol as a result of the NPN negotiation */
#ifdef USE_NPN
	SSL_get0_next_proto_negotiated(ssl, &proto, &ulen);
	LAPPEND_STR(interp, objPtr, "npn", (char *) proto, (int) ulen);
#endif

	/* Resumable session */
	LAPPEND_BOOL(interp, objPtr, "resumable", SSL_SESSION_is_resumable(session));

	/* Session start time (seconds since epoch) */
	LAPPEND_LONG(interp, objPtr, "start_time", SSL_SESSION_get_time(session));

	/* Timeout value - SSL_CTX_get_timeout (in seconds) */
	LAPPEND_LONG(interp, objPtr, "timeout", SSL_SESSION_get_timeout(session));

	/* Session id - TLSv1.2 and below only */
	session_id = SSL_SESSION_get_id(session, &ulen);
	LAPPEND_BARRAY(interp, objPtr, "session_id", session_id, (int) ulen);

	/* Session context */
	session_id = SSL_SESSION_get0_id_context(session, &ulen);
	LAPPEND_BARRAY(interp, objPtr, "session_context", session_id, (int) ulen);

	/* Session ticket - client only */
	SSL_SESSION_get0_ticket(session, &ticket, &len2);
	LAPPEND_BARRAY(interp, objPtr, "session_ticket", ticket, (int) len2);

	/* Session ticket lifetime hint (in seconds) */
	LAPPEND_LONG(interp, objPtr, "lifetime", SSL_SESSION_get_ticket_lifetime_hint(session));

	/* Ticket app data */
	SSL_SESSION_get0_ticket_appdata(session, &ticket, &len2);
	LAPPEND_BARRAY(interp, objPtr, "ticket_app_data", ticket, (int) len2);

	/* Get master key */
	len2 = SSL_SESSION_get_master_key(session, buffer, SSL_MAX_MASTER_KEY_LENGTH);
	LAPPEND_BARRAY(interp, objPtr, "master_key", buffer, (int) len2);

	/* Compression id */
	unsigned int id = SSL_SESSION_get_compress_id(session);
	LAPPEND_STR(interp, objPtr, "compression_id", id == 1 ? "zlib" : "none", -1);
    }

    /* Compression info */
    if (ssl != NULL) {
#ifdef HAVE_SSL_COMPRESSION
	const COMP_METHOD *comp, *expn;
	comp = SSL_get_current_compression(ssl);
	expn = SSL_get_current_expansion(ssl);

	LAPPEND_STR(interp, objPtr, "compression", comp ? SSL_COMP_get_name(comp) : "none", -1);
	LAPPEND_STR(interp, objPtr, "expansion", expn ? SSL_COMP_get_name(expn) : "none", -1);
#else
	LAPPEND_STR(interp, objPtr, "compression", "none", -1);
	LAPPEND_STR(interp, objPtr, "expansion", "none", -1);
#endif
    }

    /* Server info */
    {
	long mode = SSL_CTX_get_session_cache_mode(statePtr->ctx);
	char *msg;

	if (mode & SSL_SESS_CACHE_OFF) {
	    msg = "off";
	} else if (mode & SSL_SESS_CACHE_CLIENT) {
	    msg = "client";
	} else if (mode & SSL_SESS_CACHE_SERVER) {
	    msg = "server";
	} else if (mode & SSL_SESS_CACHE_BOTH) {
	    msg = "both";
	} else {
	    msg = "unknown";
	}
	LAPPEND_STR(interp, objPtr, "session_cache_mode", msg, -1);
    }

    /* CA List */
    /* IF not a server, same as SSL_get0_peer_CA_list. If server same as SSL_CTX_get_client_CA_list */
    listPtr = Tcl_NewListObj(0, NULL);
    STACK_OF(X509_NAME) *ca_list;
    if ((ca_list = SSL_get_client_CA_list(ssl)) != NULL) {
	char buffer[BUFSIZ];

	for (int i = 0; i < sk_X509_NAME_num(ca_list); i++) {
	    X509_NAME *name = sk_X509_NAME_value(ca_list, i);
	    if (name) {
		X509_NAME_oneline(name, buffer, BUFSIZ);
		Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj(buffer, -1));
	    }
	}
    }
    LAPPEND_OBJ(interp, objPtr, "caList", listPtr);
    LAPPEND_INT(interp, objPtr, "caListCount", sk_X509_NAME_num(ca_list));


    Tcl_SetObjResult(interp, objPtr);
    return TCL_OK;
	clientData = clientData;
}

/*
 *-------------------------------------------------------------------
 *
 * MiscObjCmd -- misc commands
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
MiscObjCmd(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    static const char *commands [] = { "req", "strreq", NULL };
    enum command { C_REQ, C_STRREQ, C_DUMMY };
    int cmd, isStr;
    char buffer[16384];

    dprintf("Called");

    if (objc < 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "subcommand ?args?");
	return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], commands, "command", 0, &cmd) != TCL_OK) {
	return TCL_ERROR;
    }

    ERR_clear_error();

    isStr = (cmd == C_STRREQ);
    switch ((enum command) cmd) {
	case C_REQ:
	case C_STRREQ: {
	    EVP_PKEY *pkey=NULL;
	    X509 *cert=NULL;
	    X509_NAME *name=NULL;
	    Tcl_Obj **listv;
	    int listc,i;

	    BIO *out=NULL;

	    char *k_C="",*k_ST="",*k_L="",*k_O="",*k_OU="",*k_CN="",*k_Email="";
	    char *keyout,*pemout,*str;
	    int keysize,serial=0,days=365;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	    BIGNUM *bne = NULL;
	    RSA *rsa = NULL;
#else
	    EVP_PKEY_CTX *ctx = NULL;
#endif

	    if ((objc<5) || (objc>6)) {
		Tcl_WrongNumArgs(interp, 2, objv, "keysize keyfile certfile ?info?");
		return TCL_ERROR;
	    }

	    if (Tcl_GetIntFromObj(interp, objv[2], &keysize) != TCL_OK) {
		return TCL_ERROR;
	    }
	    keyout=Tcl_GetString(objv[3]);
	    pemout=Tcl_GetString(objv[4]);
	    if (isStr) {
		Tcl_SetVar(interp,keyout,"",0);
		Tcl_SetVar(interp,pemout,"",0);
	    }

	    if (objc>=6) {
		if (Tcl_ListObjGetElements(interp, objv[5],
			&listc, &listv) != TCL_OK) {
		    return TCL_ERROR;
		}

		if ((listc%2) != 0) {
		    Tcl_SetResult(interp,"Information list must have even number of arguments",NULL);
		    return TCL_ERROR;
		}
		for (i=0; i<listc; i+=2) {
		    str=Tcl_GetString(listv[i]);
		    if (strcmp(str,"days")==0) {
			if (Tcl_GetIntFromObj(interp,listv[i+1],&days)!=TCL_OK)
			    return TCL_ERROR;
		    } else if (strcmp(str,"serial")==0) {
			if (Tcl_GetIntFromObj(interp,listv[i+1],&serial)!=TCL_OK)
			    return TCL_ERROR;
		    } else if (strcmp(str,"C")==0) {
			k_C=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"ST")==0) {
			k_ST=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"L")==0) {
			k_L=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"O")==0) {
			k_O=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"OU")==0) {
			k_OU=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"CN")==0) {
			k_CN=Tcl_GetString(listv[i+1]);
		    } else if (strcmp(str,"Email")==0) {
			k_Email=Tcl_GetString(listv[i+1]);
		    } else {
			Tcl_SetResult(interp,"Unknown parameter",NULL);
			return TCL_ERROR;
		    }
		}
	    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	    bne = BN_new();
	    rsa = RSA_new();
	    pkey = EVP_PKEY_new();
	    if (bne == NULL || rsa == NULL || pkey == NULL || !BN_set_word(bne,RSA_F4) ||
		!RSA_generate_key_ex(rsa, keysize, bne, NULL) || !EVP_PKEY_assign_RSA(pkey, rsa)) {
		EVP_PKEY_free(pkey);
		/* RSA_free(rsa); freed by EVP_PKEY_free */
		BN_free(bne);
#else
	    pkey = EVP_RSA_gen((unsigned int) keysize);
	    ctx = EVP_PKEY_CTX_new(pkey,NULL);
	    if (pkey == NULL || ctx == NULL || !EVP_PKEY_keygen_init(ctx) ||
		!EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keysize) || !EVP_PKEY_keygen(ctx, &pkey)) {
		EVP_PKEY_free(pkey);
		EVP_PKEY_CTX_free(ctx);
#endif
		Tcl_SetResult(interp,"Error generating private key",NULL);
		return TCL_ERROR;
	    } else {
		if (isStr) {
		    out=BIO_new(BIO_s_mem());
		    PEM_write_bio_PrivateKey(out,pkey,NULL,NULL,0,NULL,NULL);
		    i=BIO_read(out,buffer,sizeof(buffer)-1);
		    i=(i<0) ? 0 : i;
		    buffer[i]='\0';
		    Tcl_SetVar(interp,keyout,buffer,0);
		    BIO_flush(out);
		    BIO_free(out);
		} else {
		    out=BIO_new(BIO_s_file());
		    BIO_write_filename(out,keyout);
		    PEM_write_bio_PrivateKey(out,pkey,NULL,NULL,0,NULL,NULL);
		    /* PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL); */
		    BIO_free_all(out);
	 	}

		if ((cert=X509_new())==NULL) {
		    Tcl_SetResult(interp,"Error generating certificate request",NULL);
		    EVP_PKEY_free(pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		    BN_free(bne);
#endif
		    return(TCL_ERROR);
		}

		X509_set_version(cert,2);
		ASN1_INTEGER_set(X509_get_serialNumber(cert),serial);
		X509_gmtime_adj(X509_getm_notBefore(cert),0);
		X509_gmtime_adj(X509_getm_notAfter(cert),(long)60*60*24*days);
		X509_set_pubkey(cert,pkey);

		name=X509_get_subject_name(cert);

		X509_NAME_add_entry_by_txt(name,"C", MBSTRING_ASC, (const unsigned char *) k_C, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"ST", MBSTRING_ASC, (const unsigned char *) k_ST, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"L", MBSTRING_ASC, (const unsigned char *) k_L, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"O", MBSTRING_ASC, (const unsigned char *) k_O, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"OU", MBSTRING_ASC, (const unsigned char *) k_OU, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (const unsigned char *) k_CN, -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"Email", MBSTRING_ASC, (const unsigned char *) k_Email, -1, -1, 0);

		X509_set_subject_name(cert,name);

		if (!X509_sign(cert,pkey,EVP_sha256())) {
		    X509_free(cert);
		    EVP_PKEY_free(pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		    BN_free(bne);
#endif
		    Tcl_SetResult(interp,"Error signing certificate",NULL);
		    return TCL_ERROR;
		}

		if (isStr) {
		    out=BIO_new(BIO_s_mem());
		    PEM_write_bio_X509(out,cert);
		    i=BIO_read(out,buffer,sizeof(buffer)-1);
		    i=(i<0) ? 0 : i;
		    buffer[i]='\0';
		    Tcl_SetVar(interp,pemout,buffer,0);
		    BIO_flush(out);
		    BIO_free(out);
		} else {
		    out=BIO_new(BIO_s_file());
		    BIO_write_filename(out,pemout);
		    PEM_write_bio_X509(out,cert);
		    BIO_free_all(out);
		}

		X509_free(cert);
		EVP_PKEY_free(pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		BN_free(bne);
#endif
	    }
	}
	break;
    default:
	break;
    }
    return TCL_OK;
	clientData = clientData;
}

/********************/
/* Init             */
/********************/

/*
 *-------------------------------------------------------------------
 *
 * Tls_Free --
 *
 *	This procedure cleans up when a SSL socket based channel
 *	is closed and its reference count falls below 1
 *
 * Results:
 *	none
 *
 * Side effects:
 *	Frees all the state
 *
 *-------------------------------------------------------------------
 */
void
Tls_Free(char *blockPtr) {
    State *statePtr = (State *)blockPtr;

    dprintf("Called");

    Tls_Clean(statePtr);
    ckfree(blockPtr);
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Clean --
 *
 *	This procedure cleans up when a SSL socket based channel
 *	is closed and its reference count falls below 1.  This should
 *	be called synchronously by the CloseProc, not in the
 *	EventuallyFree callback.
 *
 * Results:
 *	none
 *
 * Side effects:
 *	Frees all the state
 *
 *-------------------------------------------------------------------
 */
void Tls_Clean(State *statePtr) {
    dprintf("Called");

    /*
     * we're assuming here that we're single-threaded
     */
    if (statePtr->timer != (Tcl_TimerToken) NULL) {
	Tcl_DeleteTimerHandler(statePtr->timer);
	statePtr->timer = NULL;
    }

    if (statePtr->protos) {
	ckfree(statePtr->protos);
	statePtr->protos = NULL;
    }
    if (statePtr->bio) {
	/* This will call SSL_shutdown. Bug 1414045 */
	dprintf("BIO_free_all(%p)", statePtr->bio);
	BIO_free_all(statePtr->bio);
	statePtr->bio = NULL;
    }
    if (statePtr->ssl) {
	dprintf("SSL_free(%p)", statePtr->ssl);
	SSL_free(statePtr->ssl);
	statePtr->ssl = NULL;
    }
    if (statePtr->ctx) {
	SSL_CTX_free(statePtr->ctx);
	statePtr->ctx = NULL;
    }
    if (statePtr->callback) {
	Tcl_DecrRefCount(statePtr->callback);
	statePtr->callback = NULL;
    }
    if (statePtr->password) {
	Tcl_DecrRefCount(statePtr->password);
	statePtr->password = NULL;
    }
    if (statePtr->vcmd) {
	Tcl_DecrRefCount(statePtr->vcmd);
	statePtr->vcmd = NULL;
    }

    dprintf("Returning");
}

/*
 *-------------------------------------------------------------------
 *
 * Tls_Init --
 *
 *	This is a package initialization procedure, which is called
 *	by Tcl when this package is to be added to an interpreter.
 *
 * Results:  Ssl configured and loaded
 *
 * Side effects:
 *	 create the ssl command, initialize ssl context
 *
 *-------------------------------------------------------------------
 */
DLLEXPORT int Tls_Init(Tcl_Interp *interp) {
    const char tlsTclInitScript[] = {
#include "tls.tcl.h"
	0x00
    };

    dprintf("Called");

#if TCL_MAJOR_VERSION > 8
#ifdef USE_TCL_STUBS
    if (Tcl_InitStubs(interp, "9.0", 0) == NULL) {
	return TCL_ERROR;
    }
#endif
    if (Tcl_PkgRequire(interp, "Tcl", "9.0-", 0) == NULL) {
	return TCL_ERROR;
    }
#else
#ifdef USE_TCL_STUBS
    if (Tcl_InitStubs(interp, "8.5", 0) == NULL) {
	return TCL_ERROR;
    }
#endif
    if (Tcl_PkgRequire(interp, "Tcl", "8.5-", 0) == NULL) {
	return TCL_ERROR;
    }
#endif

    if (TlsLibInit(0) != TCL_OK) {
	Tcl_AppendResult(interp, "could not initialize SSL library", NULL);
	return TCL_ERROR;
    }

    Tcl_CreateObjCommand(interp, "tls::connection", ConnectionInfoObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::handshake", HandshakeObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::import", ImportObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::misc", MiscObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::unimport", UnimportObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "tls::status", StatusObjCmd, (ClientData) 0, (Tcl_CmdDeleteProc *) NULL);

    Tls_DigestCommands(interp);
    Tls_EncryptCommands(interp);
    Tls_InfoCommands(interp);
    Tls_KeyCommands(interp);

    if (interp) {
	Tcl_Eval(interp, tlsTclInitScript);
    }

    return Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION);
}

/*
 *------------------------------------------------------*
 *
 *	Tls_SafeInit --
 *
 *	------------------------------------------------*
 *	Standard procedure required by 'load'.
 *	Initializes this extension for a safe interpreter.
 *	------------------------------------------------*
 *
 *	Side effects:
 *		As of 'Tls_Init'
 *
 *	Result:
 *		A standard Tcl error code.
 *
 *------------------------------------------------------*
 */
DLLEXPORT int Tls_SafeInit(Tcl_Interp *interp) {
    dprintf("Called");
    return(Tls_Init(interp));
}

/*
 *------------------------------------------------------*
 *
 *	TlsLibInit --
 *
 *	------------------------------------------------*
 *	Initializes SSL library once per application
 *	------------------------------------------------*
 *
 *	Side effects:
 *		initializes SSL library
 *
 *	Result:
 *		none
 *
 *------------------------------------------------------*
 */
static int TlsLibInit(int uninitialize) {
    static int initialized = 0;
    int status = TCL_OK;
#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
    size_t num_locks;
#endif

    if (uninitialize) {
	if (!initialized) {
	    dprintf("Asked to uninitialize, but we are not initialized");

	    return(TCL_OK);
	}

	dprintf("Asked to uninitialize");

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
	Tcl_MutexLock(&init_mx);

	if (locks) {
	    free(locks);
	    locks = NULL;
	    locksCount = 0;
	}
#endif
	initialized = 0;

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
	Tcl_MutexUnlock(&init_mx);
#endif

	return(TCL_OK);
    }

    if (initialized) {
	dprintf("Called, but using cached value");
	return(status);
    }

    dprintf("Called");

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
    Tcl_MutexLock(&init_mx);
#endif
    initialized = 1;

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
    num_locks = 1;
    locksCount = (int) num_locks;
    locks = malloc(sizeof(*locks) * num_locks);
    memset(locks, 0, sizeof(*locks) * num_locks);
#endif

    /* Initialize BOTH libcrypto and libssl. */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS
	| OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

    BIO_new_tcl(NULL, 0);

#if 0
    /*
     * XXX:TODO: Remove this code and replace it with a check
     * for enough entropy and do not try to create our own
     * terrible entropy
     */
    /*
     * Seed the random number generator in the SSL library,
     * using the do/while construct because of the bug note in the
     * OpenSSL FAQ at http://www.openssl.org/support/faq.html#USER1
     *
     * The crux of the problem is that Solaris 7 does not have a
     * /dev/random or /dev/urandom device so it cannot gather enough
     * entropy from the RAND_seed() when TLS initializes and refuses
     * to go further. Earlier versions of OpenSSL carried on regardless.
     */
    srand((unsigned int) time((time_t *) NULL));
    do {
	for (i = 0; i < 16; i++) {
	    rnd_seed[i] = 1 + (char) (255.0 * rand()/(RAND_MAX+1.0));
	}
	RAND_seed(rnd_seed, sizeof(rnd_seed));
    } while (RAND_status() != 1);
#endif

#if defined(OPENSSL_THREADS) && defined(TCL_THREADS)
	Tcl_MutexUnlock(&init_mx);
#endif

	return(status);
}
