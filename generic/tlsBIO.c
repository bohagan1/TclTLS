/*
 * Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
 *
 * Provides BIO layer to interface openssl to Tcl.
 */

#include "tlsInt.h"

static int BioWrite(BIO *bio, const char *buf, int bufLen) {
    Tcl_Channel chan;
    Tcl_Size ret;
    int tclEofChan, tclErrno;

    chan = Tls_GetParent((State *) BIO_get_data(bio), 0);

    dprintf("[chan=%p] BioWrite(%p, <buf>, %d)", (void *)chan, (void *) bio, bufLen);

    ret = Tcl_WriteRaw(chan, buf, (Tcl_Size) bufLen);

    tclEofChan = Tcl_Eof(chan);
    tclErrno = Tcl_GetErrno();

    dprintf("[chan=%p] BioWrite(%d) -> %" TCL_SIZE_MODIFIER "d [tclEof=%d; tclErrno=%d]",
	(void *) chan, bufLen, ret, tclEofChan, Tcl_GetErrno());

    BIO_clear_flags(bio, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY);

    if (tclEofChan && ret <= 0) {
	dprintf("Got EOF while reading, returning a Connection Reset error which maps to Soft EOF");
	Tcl_SetErrno(ECONNRESET);
	ret = 0;

    } else if (ret == 0) {
	dprintf("Got 0 from Tcl_WriteRaw, and EOF is not set; ret = 0");
	dprintf("Setting retry read flag");
	BIO_set_retry_read(bio);

    } else if (ret < 0) {
	dprintf("We got some kind of I/O error");

	if (tclErrno == EAGAIN) {
	    dprintf("It's EAGAIN");
	} else {
	    dprintf("It's an unexpected error: %s/%i", Tcl_ErrnoMsg(tclErrno), tclErrno);
	}

    } else {
	dprintf("Successfully wrote some data");
    }

    if (ret != -1 || (ret == -1 && tclErrno == EAGAIN)) {
	if (BIO_should_read(bio)) {
	    dprintf("Setting should retry read flag");

	    BIO_set_retry_read(bio);
	}
    }
    return((int) ret);
}

static int BioRead(BIO *bio, char *buf, int bufLen) {
    Tcl_Channel chan;
    Tcl_Size ret = 0;
    int tclEofChan, tclErrno;

    chan = Tls_GetParent((State *) BIO_get_data(bio), 0);

    dprintf("[chan=%p] BioRead(%p, <buf>, %d)", (void *) chan, (void *) bio, bufLen);

    if (buf == NULL) {
	return 0;
    }

    ret = Tcl_ReadRaw(chan, buf, (Tcl_Size) bufLen);

    tclEofChan = Tcl_Eof(chan);
    tclErrno = Tcl_GetErrno();

    dprintf("[chan=%p] BioRead(%d) -> %" TCL_SIZE_MODIFIER "d [tclEof=%d; tclErrno=%d]",
	(void *) chan, bufLen, ret, tclEofChan, tclErrno);

    BIO_clear_flags(bio, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);

    if (tclEofChan && ret <= 0) {
	dprintf("Got EOF while reading, returning a Connection Reset error which maps to Soft EOF");
	Tcl_SetErrno(ECONNRESET);
	ret = 0;

    } else if (ret == 0) {
	dprintf("Got 0 from Tcl_Read or Tcl_ReadRaw, and EOF is not set; ret = 0");
	dprintf("Setting retry read flag");
	BIO_set_retry_read(bio);

    } else if (ret < 0) {
	dprintf("We got some kind of I/O error");

	if (tclErrno == EAGAIN) {
	    dprintf("It's EAGAIN");
	} else {
	    dprintf("It's an unexpected error: %s/%i", Tcl_ErrnoMsg(tclErrno), tclErrno);
	}

    } else {
	dprintf("Successfully read some data");
    }

    if (ret != -1 || (ret == -1 && tclErrno == EAGAIN)) {
	if (BIO_should_write(bio)) {
	    dprintf("Setting should retry write flag");

	    BIO_set_retry_write(bio);
	}
    }

    dprintf("BioRead(%p, <buf>, %d) [%p] returning %" TCL_SIZE_MODIFIER "d", (void *) bio,
	bufLen, (void *) chan, ret);

    return((int) ret);
}

static int BioPuts(BIO *bio, const char *str) {
    dprintf("BioPuts(%p, <string:%p>) called", bio, str);

    return BioWrite(bio, str, (int) strlen(str));
}

static long BioCtrl(BIO *bio, int cmd, long num, void *ptr) {
    Tcl_Channel chan;
    long ret = 1;

    chan = Tls_GetParent((State *) BIO_get_data(bio), 0);

    dprintf("BioCtrl(%p, 0x%x, 0x%lx, %p)", (void *) bio, cmd, num, ptr);

    switch (cmd) {
	case BIO_CTRL_RESET:
		dprintf("Got BIO_CTRL_RESET");
		num = 0;
		ret = 0;
		break;
	case BIO_C_FILE_SEEK:
		dprintf("Got BIO_C_FILE_SEEK");
		ret = 0;
		break;
	case BIO_C_FILE_TELL:
		dprintf("Got BIO_C_FILE_TELL");
		ret = 0;
		break;
	case BIO_CTRL_INFO:
		dprintf("Got BIO_CTRL_INFO");
		ret = 1;
		break;
	case BIO_C_SET_FD:
		dprintf("Unsupported call: BIO_C_SET_FD");
		ret = -1;
		break;
	case BIO_C_GET_FD:
		dprintf("Unsupported call: BIO_C_GET_FD");
		ret = -1;
		break;
	case BIO_CTRL_GET_CLOSE:
		dprintf("Got BIO_CTRL_CLOSE");
		ret = BIO_get_shutdown(bio);
		break;
	case BIO_CTRL_SET_CLOSE:
		dprintf("Got BIO_SET_CLOSE");
		BIO_set_shutdown(bio, num);
		break;
	case BIO_CTRL_EOF:
		dprintf("Got BIO_CTRL_EOF");
		ret = ((chan) ? Tcl_Eof(chan) : 1);
		break;
	case BIO_CTRL_PENDING:
		dprintf("Got BIO_CTRL_PENDING");
		ret = ((chan) ? ((Tcl_InputBuffered(chan) ? 1 : 0)) : 0);
		dprintf("BIO_CTRL_PENDING(%d)", (int) ret);
		break;
	case BIO_CTRL_WPENDING:
		dprintf("Got BIO_CTRL_WPENDING");
		ret = 0;
		break;
	case BIO_CTRL_DUP:
		dprintf("Got BIO_CTRL_DUP");
		break;
	case BIO_CTRL_FLUSH:
		dprintf("Got BIO_CTRL_FLUSH");
		ret = ((chan) && (Tcl_WriteRaw(chan, "", 0) >= 0) ? 1 : -1);
		dprintf("BIO_CTRL_FLUSH returning value %li", ret);
		break;
	case BIO_CTRL_PUSH:
		dprintf("Got BIO_CTRL_PUSH");
		ret = 0;
		break;
	case BIO_CTRL_POP:
		dprintf("Got BIO_CTRL_POP");
		ret = 0;
		break;
	case BIO_CTRL_SET:
		dprintf("Got BIO_CTRL_SET");
		ret = 0;
		break;
	case BIO_CTRL_GET :
		dprintf("Got BIO_CTRL_GET ");
		ret = 0;
		break;
#ifdef BIO_CTRL_GET_KTLS_SEND
	case BIO_CTRL_GET_KTLS_SEND:
		dprintf("Got BIO_CTRL_GET_KTLS_SEND");
		ret = 0;
		break;
#endif
#ifdef BIO_CTRL_GET_KTLS_RECV
	case BIO_CTRL_GET_KTLS_RECV:
		dprintf("Got BIO_CTRL_GET_KTLS_RECV");
		ret = 0;
		break;
#endif
	default:
		dprintf("Got unknown control command (%i)", cmd);
		ret = 0;
		break;
    }
    return(ret);
}

static int BioNew(BIO *bio) {
    dprintf("BioNew(%p) called", bio);

    BIO_set_init(bio, 0);
    BIO_set_data(bio, NULL);
    BIO_clear_flags(bio, -1);
    return(1);
}

static int BioFree(BIO *bio) {
    if (bio == NULL) {
	return(0);
    }

    dprintf("BioFree(%p) called", bio);

    if (BIO_get_shutdown(bio)) {
	if (BIO_get_init(bio)) {
	    /*shutdown(bio->num, 2) */
	    /*closesocket(bio->num) */
	}

	BIO_set_init(bio, 0);
	BIO_clear_flags(bio, -1);
    }
    return(1);
}

BIO *BIO_new_tcl(State *statePtr, int flags) {
    BIO *bio;
    static BIO_METHOD *BioMethods = NULL;
#ifdef TCLTLS_SSL_USE_FASTPATH
    Tcl_Channel parentChannel;
    const Tcl_ChannelType *parentChannelType;
    void *parentChannelFdIn_p, *parentChannelFdOut_p;
    int parentChannelFdIn, parentChannelFdOut, parentChannelFd;
    int validParentChannelFd;
    int tclGetChannelHandleRet;
#endif

    dprintf("BIO_new_tcl() called");

    if (BioMethods == NULL) {
	BioMethods = BIO_meth_new(BIO_TYPE_TCL, "tcl");
	BIO_meth_set_write(BioMethods, BioWrite);
	BIO_meth_set_read(BioMethods, BioRead);
	BIO_meth_set_puts(BioMethods, BioPuts);
	BIO_meth_set_ctrl(BioMethods, BioCtrl);
	BIO_meth_set_create(BioMethods, BioNew);
	BIO_meth_set_destroy(BioMethods, BioFree);
    }

    if (statePtr == NULL) {
	dprintf("Asked to setup a NULL state, just creating the initial configuration");

	return(NULL);
    }

#ifdef TCLTLS_SSL_USE_FASTPATH
    /*
     * If the channel can be mapped back to a file descriptor, just use the file descriptor
     * with the SSL library since it will likely be optimized for this.
     */
    parentChannel = Tls_GetParent(statePtr, 0);
    parentChannelType = Tcl_GetChannelType(parentChannel);

    validParentChannelFd = 0;
    if (strcmp(parentChannelType->typeName, "tcp") == 0) {
	tclGetChannelHandleRet = Tcl_GetChannelHandle(parentChannel, TCL_READABLE, (ClientData) &parentChannelFdIn_p);
	if (tclGetChannelHandleRet == TCL_OK) {
	    tclGetChannelHandleRet = Tcl_GetChannelHandle(parentChannel, TCL_WRITABLE, (ClientData) &parentChannelFdOut_p);
	    if (tclGetChannelHandleRet == TCL_OK) {
		parentChannelFdIn = PTR2INT(parentChannelFdIn_p);
		parentChannelFdOut = PTR2INT(parentChannelFdOut_p);
		if (parentChannelFdIn == parentChannelFdOut) {
		    parentChannelFd = parentChannelFdIn;
		    validParentChannelFd = 1;
		}
	    }
	}
    }

    if (validParentChannelFd) {
	dprintf("We found a shortcut, this channel is backed by a socket: %i", parentChannelFdIn);
	bio = BIO_new_socket(parentChannelFd, flags);
	statePtr->flags |= TLS_TCL_FASTPATH;
	return(bio);
    }

    dprintf("Falling back to Tcl I/O for this channel");
#endif

    bio = BIO_new(BioMethods);
    BIO_set_data(bio, statePtr);
    BIO_set_shutdown(bio, flags);
    BIO_set_init(bio, 1);
    return(bio);
}
