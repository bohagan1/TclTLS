/*
 * Convenient option processing
 */

#ifndef _TCL_OPTS_H
#define _TCL_OPTS_H

#define GET_OPT_BOOL(objPtr, varPtr) \
    if (Tcl_GetBooleanFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_INT(objPtr, varPtr) \
    if (Tcl_GetIntFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_LONG(objPtr, varPtr) \
    if (Tcl_GetLongFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_WIDE(objPtr, varPtr) \
    if (Tcl_GetWideIntFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_BIGNUM(objPtr, varPtr) \
    if (Tcl_GetBignumFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_STRING(objPtr, var, lenPtr) \
    if ((var = Tcl_GetStringFromObj(objPtr, lenPtr)) == NULL) {	\
	return TCL_ERROR;					\
    }								\

#define GET_OPT_BYTE_ARRAY(objPtr, var, lenPtr) \
    if ((var = Tcl_GetByteArrayFromObj(objPtr, lenPtr)) == NULL) {	\
	return TCL_ERROR;					\
    }								\

#endif /* _TCL_OPTS_H */
