/*
 * Copyright (C) 1997-2000 Sensus Consulting Ltd.
 * Matt Newman <matt@sensus.org>
 * Copyright (C) 2023 Brian O'Hagan
 */
#include <tcl.h>
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/asn1.h>
#include "tlsInt.h"

/* Define maximum certificate size. Max PEM size 100kB and DER size is 24kB. */
#define CERT_STR_SIZE 32768


/*
 * Binary string to hex string
 */
int String_to_Hex(unsigned char* input, int ilen, unsigned char *output, int olen) {
    int count = 0;
    unsigned char *iptr = input;
    unsigned char *optr = &output[0];
    const char *hex = "0123456789abcdef";

    for (int i = 0; i < ilen && count < olen - 1; i++, count += 2) {
        *optr++ = hex[(*iptr>>4)&0xF];
        *optr++ = hex[(*iptr++)&0xF];
    }
    *optr = 0;
    return count;
}

/*
 * BIO to Buffer
 */
int BIO_to_Buffer(int result, BIO *bio, void *buffer, int size) {
    int len = 0;
    int pending = BIO_pending(bio);

    if (result) {
	len = BIO_read(bio, buffer, (pending < size) ? pending : size);
	(void)BIO_flush(bio);
	if (len < 0) {
	    len = 0;
	}
    }
    return len;
}

/*
 * Get X509 Certificate Extensions
 */
Tcl_Obj *Tls_x509Extensions(Tcl_Interp *interp, X509 *cert) {
    const STACK_OF(X509_EXTENSION) *exts;
    Tcl_Obj *listPtr = Tcl_NewListObj(0, NULL);

    if (listPtr == NULL) {
	return NULL;
    }

    if ((exts = X509_get0_extensions(cert)) != NULL) {
	for (int i=0; i < X509_get_ext_count(cert); i++) {
	    X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
	    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
	    /* ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(ex); */
	    int critical = X509_EXTENSION_get_critical(ex);
	    LAPPEND_BOOL(interp, listPtr, OBJ_nid2ln(OBJ_obj2nid(obj)), critical);
	}
    }
    return listPtr;
}

/*
 * Get Authority and Subject Key Identifiers
 */
Tcl_Obj *Tls_x509Identifier(const ASN1_OCTET_STRING *astring) {
    Tcl_Obj *resultPtr = NULL;
    int len = 0;
    unsigned char buffer[1024];

    if (astring != NULL) {
	len = String_to_Hex((unsigned char *) ASN1_STRING_get0_data(astring),
	    ASN1_STRING_length(astring), buffer, 1024);
    }
    resultPtr = Tcl_NewStringObj((char *) &buffer[0], (Tcl_Size) len);
    return resultPtr;
}

/*
 * Get Key Usage
 */
Tcl_Obj *Tls_x509KeyUsage(Tcl_Interp *interp, X509 *cert, uint32_t xflags) {
    uint32_t usage = X509_get_key_usage(cert);
    Tcl_Obj *listPtr = Tcl_NewListObj(0, NULL);

    if (listPtr == NULL) {
	return NULL;
    }

    if ((xflags & EXFLAG_KUSAGE) && usage < UINT32_MAX) {
	if (usage & KU_DIGITAL_SIGNATURE) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Digital Signature", -1));
	}
	if (usage & KU_NON_REPUDIATION) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Non-Repudiation", -1));
	}
	if (usage & KU_KEY_ENCIPHERMENT) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Key Encipherment", -1));
	}
	if (usage & KU_DATA_ENCIPHERMENT) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Data Encipherment", -1));
	}
	if (usage & KU_KEY_AGREEMENT) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Key Agreement", -1));
	}
	if (usage & KU_KEY_CERT_SIGN) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Certificate Signing", -1));
	}
	if (usage & KU_CRL_SIGN) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("CRL Signing", -1));
	}
	if (usage & KU_ENCIPHER_ONLY) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Encipher Only", -1));
	}
	if (usage & KU_DECIPHER_ONLY) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Decipher Only", -1));
	}
    } else {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("unrestricted", -1));
    }
    return listPtr;
}

/*
 * Get Certificate Purpose
 */
char *Tls_x509Purpose(X509 *cert) {
    char *purpose = NULL;

    if (X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 0) > 0) {
	purpose = "SSL Client";
    } else if (X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 0) > 0) {
	purpose = "SSL Server";
    } else if (X509_check_purpose(cert, X509_PURPOSE_NS_SSL_SERVER, 0) > 0) {
	purpose = "MSS SSL Server";
    } else if (X509_check_purpose(cert, X509_PURPOSE_SMIME_SIGN, 0) > 0) {
	purpose = "SMIME Signing";
    } else if (X509_check_purpose(cert, X509_PURPOSE_SMIME_ENCRYPT, 0) > 0) {
	purpose = "SMIME Encryption";
    } else if (X509_check_purpose(cert, X509_PURPOSE_CRL_SIGN, 0) > 0) {
	purpose = "CRL Signing";
    } else if (X509_check_purpose(cert, X509_PURPOSE_ANY, 0) > 0) {
	purpose = "Any";
    } else if (X509_check_purpose(cert, X509_PURPOSE_OCSP_HELPER, 0) > 0) {
	purpose = "OCSP Helper";
    } else if (X509_check_purpose(cert, X509_PURPOSE_TIMESTAMP_SIGN, 0) > 0) {
	purpose = "Timestamp Signing";
    } else {
	purpose = "";
    }
    return purpose;
}

/*
 * For each purpose, get certificate applicability
 */
Tcl_Obj *Tls_x509Purposes(Tcl_Interp *interp, X509 *cert) {
    Tcl_Obj *listPtr = Tcl_NewListObj(0, NULL);
    X509_PURPOSE *ptmp;

    if (listPtr == NULL) {
	return NULL;
    }

    for (int i = 0; i < X509_PURPOSE_get_count(); i++) {
	ptmp = X509_PURPOSE_get0(i);
	Tcl_Obj *tmpPtr = Tcl_NewListObj(0, NULL);

	for (int j = 0; j < 2; j++) {
	    int idret = X509_check_purpose(cert, X509_PURPOSE_get_id(ptmp), j);
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj(j ? "CA" : "nonCA", -1));
	    Tcl_ListObjAppendElement(interp, tmpPtr, Tcl_NewStringObj(idret == 1 ? "Yes" : "No", -1));
	}
	LAPPEND_OBJ(interp, listPtr, X509_PURPOSE_get0_name(ptmp), tmpPtr);
    }
    return listPtr;
}

/*
 * Get Subject Alternate Names (SAN) and Issuer Alternate Names
 */
Tcl_Obj *Tls_x509Names(Tcl_Interp *interp, X509 *cert, int nid, BIO *bio) {
    STACK_OF(GENERAL_NAME) *names;
    Tcl_Obj *listPtr = Tcl_NewListObj(0, NULL);
    int len;
    char buffer[1024];

    if (listPtr == NULL) {
	return NULL;
    }

    if ((names = X509_get_ext_d2i(cert, nid, NULL, NULL)) != NULL) {
	for (int i=0; i < sk_GENERAL_NAME_num(names); i++) {
	    const GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

	    len = BIO_to_Buffer(name && GENERAL_NAME_print(bio, (GENERAL_NAME *) name), bio, buffer, 1024);
	    LAPPEND_STR(interp, listPtr, NULL, buffer, (Tcl_Size) len);
	}
	sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
    }
    return listPtr;
}

/*
 * Get EXtended Key Usage
 */
Tcl_Obj *Tls_x509ExtKeyUsage(Tcl_Interp *interp, X509 *cert, uint32_t xflags) {
    uint32_t usage = X509_get_key_usage(cert);
    Tcl_Obj *listPtr = Tcl_NewListObj(0, NULL);

    if (listPtr == NULL) {
	return NULL;
    }

    if ((xflags & EXFLAG_XKUSAGE) && usage < UINT32_MAX) {
	usage = X509_get_extended_key_usage(cert);

	if (usage & XKU_SSL_SERVER) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("TLS Web Server Authentication", -1));
	}
	if (usage & XKU_SSL_CLIENT) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("TLS Web Client Authentication", -1));
	}
	if (usage & XKU_SMIME) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("E-mail Protection", -1));
	}
	if (usage & XKU_CODE_SIGN) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Code Signing", -1));
	}
	if (usage & XKU_SGC) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("SGC", -1));
	}
	if (usage & XKU_OCSP_SIGN) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("OCSP Signing", -1));
	}
	if (usage & XKU_TIMESTAMP) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Time Stamping", -1));
	}
	if (usage & XKU_DVCS ) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("DVCS", -1));
	}
	if (usage & XKU_ANYEKU) {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("Any Extended Key Usage", -1));
	}
    } else {
	    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj("unrestricted", -1));
    }
    return listPtr;
}

/*
 * Get CRL Distribution Points
 */
Tcl_Obj *Tls_x509CrlDp(Tcl_Interp *interp, X509 *cert) {
    STACK_OF(DIST_POINT) *crl;
    Tcl_Obj *listPtr = Tcl_NewListObj(0, NULL);

    if (listPtr == NULL) {
	return NULL;
    }

    if ((crl = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL)) != NULL) {
	for (int i=0; i < sk_DIST_POINT_num(crl); i++) {
	    DIST_POINT *dp = sk_DIST_POINT_value(crl, i);
	    DIST_POINT_NAME *distpoint = dp->distpoint;

	    if (distpoint->type == 0) {
		/* full-name GENERALIZEDNAME */
		for (int j = 0; j < sk_GENERAL_NAME_num(distpoint->name.fullname); j++) {
		    GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, j);
		    int type;
		    ASN1_STRING *uri = GENERAL_NAME_get0_value(gen, &type);
		    if (type == GEN_URI) {
			LAPPEND_STR(interp, listPtr, (char *) NULL, (char *) ASN1_STRING_get0_data(uri), (Tcl_Size) ASN1_STRING_length(uri));
		    }
		}
	    } else if (distpoint->type == 1) {
		/* relative-name X509NAME */
		STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
		for (int j = 0; j < sk_X509_NAME_ENTRY_num(sk_relname); j++) {
		    X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, j);
		    ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
		    LAPPEND_STR(interp, listPtr, (char *) NULL, (char *) ASN1_STRING_data(d), (Tcl_Size) ASN1_STRING_length(d));
		}
	    }
	}
	CRL_DIST_POINTS_free(crl);
    }
    return listPtr;
}

/*
 * Get On-line Certificate Status Protocol (OSCP) URL
 */
Tcl_Obj *Tls_x509Oscp(Tcl_Interp *interp, X509 *cert) {
    STACK_OF(OPENSSL_STRING) *ocsp;
    Tcl_Obj *listPtr = Tcl_NewListObj(0, NULL);

    if (listPtr == NULL) {
	return NULL;
    }

    if ((ocsp = X509_get1_ocsp(cert)) != NULL) {
	for (int i = 0; i < sk_OPENSSL_STRING_num(ocsp); i++) {
	    LAPPEND_STR(interp, listPtr, NULL, sk_OPENSSL_STRING_value(ocsp, i), -1);
	}
	X509_email_free(ocsp);
    }
    return listPtr;
}

/*
 * Get Certificate Authority (CA) Issuers URL
 */
Tcl_Obj *Tls_x509CaIssuers(Tcl_Interp *interp, X509 *cert) {
    STACK_OF(ACCESS_DESCRIPTION) *ads;
    ACCESS_DESCRIPTION *ad;
    Tcl_Obj *listPtr = Tcl_NewListObj(0, NULL);
    unsigned char *buf;
    int len;

    if ((ads = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL)) != NULL) {
	for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(ads); i++) {
	    ad = sk_ACCESS_DESCRIPTION_value(ads, i);
	    if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers && ad->location) {
		if (ad->location->type == GEN_URI) {
		    len = ASN1_STRING_to_UTF8(&buf, ad->location->d.uniformResourceIdentifier);
		    Tcl_ListObjAppendElement(interp, listPtr, Tcl_NewStringObj((char *) buf, (Tcl_Size) len));
		    OPENSSL_free(buf);
		    break;
		}
	    }
	}
	/* sk_ACCESS_DESCRIPTION_pop_free(ads, ACCESS_DESCRIPTION_free); */
	AUTHORITY_INFO_ACCESS_free(ads);
    }
    return listPtr;
}

/*
 *------------------------------------------------------*
 *
 *	Tls_NewX509Obj --
 *
 *	------------------------------------------------*
 *	Converts a X509 certificate into a Tcl_Obj
 *	------------------------------------------------*
 *
 *	Side effects:
 *		None
 *
 *	Result:
 *		A Tcl List Object representing the provided
 *		X509 certificate.
 *
 *------------------------------------------------------*
 */

Tcl_Obj*
Tls_NewX509Obj(Tcl_Interp *interp, X509 *cert) {
    Tcl_Obj *certPtr = Tcl_NewListObj(0, NULL);
    BIO *bio = BIO_new(BIO_s_mem());
    int mdnid, pknid, bits, len;
    unsigned int ulen;
    uint32_t xflags;
    char buffer[BUFSIZ];
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned long flags = XN_FLAG_RFC2253 | ASN1_STRFLGS_UTF8_CONVERT;
    flags &= ~ASN1_STRFLGS_ESC_MSB;

    if (interp == NULL || cert == NULL || bio == NULL || certPtr == NULL) {
	return NULL;
    }

    /* Signature algorithm and value - RFC 5280 section 4.1.1.2 and 4.1.1.3 */
    /* signatureAlgorithm is the id of the cryptographic algorithm used by the
	CA to sign this cert. signatureValue is the digital signature computed
	upon the ASN.1 DER encoded tbsCertificate. */
    {
	const X509_ALGOR *sig_alg;
	const ASN1_BIT_STRING *sig;
	int sig_nid;

	X509_get0_signature(&sig, &sig_alg, cert);
	/* sig_nid = X509_get_signature_nid(cert) */
	sig_nid = OBJ_obj2nid(sig_alg->algorithm);
	LAPPEND_STR(interp, certPtr, "signatureAlgorithm", OBJ_nid2ln(sig_nid), -1);
	len = (sig_nid != NID_undef) ? String_to_Hex(sig->data, sig->length, (unsigned char *) buffer, BUFSIZ) : 0;
	LAPPEND_STR(interp, certPtr, "signatureValue", buffer, (Tcl_Size) len);
    }

    /* Version of the encoded certificate - RFC 5280 section 4.1.2.1 */
    LAPPEND_LONG(interp, certPtr, "version", X509_get_version(cert)+1);

    /* Unique number assigned by CA to certificate - RFC 5280 section 4.1.2.2 */
    len = BIO_to_Buffer(i2a_ASN1_INTEGER(bio, X509_get0_serialNumber(cert)), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "serialNumber", buffer, (Tcl_Size) len);

    /* Signature algorithm used by the CA to sign the certificate. Must match
	signatureAlgorithm. RFC 5280 section 4.1.2.3 */
    LAPPEND_STR(interp, certPtr, "signature", OBJ_nid2ln(X509_get_signature_nid(cert)), -1);

    /* Issuer identifies the entity that signed and issued the cert. RFC 5280 section 4.1.2.4 */
    len = BIO_to_Buffer(X509_NAME_print_ex(bio, X509_get_issuer_name(cert), 0, flags), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "issuer", buffer, (Tcl_Size) len);

    /* Certificate validity period is the interval the CA warrants that it will
	maintain info on the status of the certificate. RFC 5280 section 4.1.2.5 */
    /* Get Validity - Not Before */
    len = BIO_to_Buffer(ASN1_TIME_print(bio, X509_get0_notBefore(cert)), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "notBefore", buffer, (Tcl_Size) len);

    /* Get Validity - Not After */
    len = BIO_to_Buffer(ASN1_TIME_print(bio, X509_get0_notAfter(cert)), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "notAfter", buffer, (Tcl_Size) len);

    /* Subject identifies the entity associated with the public key stored in
	the subject public key field. RFC 5280 section 4.1.2.6 */
    len = BIO_to_Buffer(X509_NAME_print_ex(bio, X509_get_subject_name(cert), 0, flags), bio, buffer, BUFSIZ);
    LAPPEND_STR(interp, certPtr, "subject", buffer, (Tcl_Size) len);

    /* SHA1 Digest (Fingerprint) of cert - DER representation */
    if (X509_digest(cert, EVP_sha1(), md, &ulen)) {
	len = String_to_Hex(md, len, (unsigned char *) buffer, BUFSIZ);
	LAPPEND_STR(interp, certPtr, "sha1_hash", buffer, (Tcl_Size) ulen);
    }

    /* SHA256 Digest (Fingerprint) of cert - DER representation */
    if (X509_digest(cert, EVP_sha256(), md, &ulen)) {
	len = String_to_Hex(md, len, (unsigned char *) buffer, BUFSIZ);
	LAPPEND_STR(interp, certPtr, "sha256_hash", buffer, (Tcl_Size) ulen);
    }

    /* Subject Public Key Info specifies the public key and identifies the
	algorithm with which the key is used. RFC 5280 section 4.1.2.7 */
    if (X509_get_signature_info(cert, &mdnid, &pknid, &bits, &xflags)) {
	ASN1_BIT_STRING *key;
	unsigned int n;

	LAPPEND_STR(interp, certPtr, "signingDigest", OBJ_nid2ln(mdnid), -1);
	LAPPEND_STR(interp, certPtr, "publicKeyAlgorithm", OBJ_nid2ln(pknid), -1);
	LAPPEND_INT(interp, certPtr, "bits", bits); /* Effective security bits */

	key = X509_get0_pubkey_bitstr(cert);
	len = String_to_Hex(key->data, key->length, (unsigned char *) buffer, BUFSIZ);
	LAPPEND_STR(interp, certPtr, "publicKey", buffer, (Tcl_Size) len);

	len = 0;
	if (X509_pubkey_digest(cert, EVP_get_digestbynid(pknid), md, &n)) {
	    len = String_to_Hex(md, (int) n, (unsigned char *) buffer, BUFSIZ);
	}
	LAPPEND_STR(interp, certPtr, "publicKeyHash", buffer, (Tcl_Size) len);

	/* digest of the DER representation of the certificate */
	len = 0;
	if (X509_digest(cert, EVP_get_digestbynid(mdnid), md, &n)) {
	    len = String_to_Hex(md, (int) n, (unsigned char *) buffer, BUFSIZ);
	}
	LAPPEND_STR(interp, certPtr, "signatureHash", buffer, (Tcl_Size) len);
    }

    /* Certificate Purpose. Call before checking for extensions. */
    LAPPEND_STR(interp, certPtr, "purpose", Tls_x509Purpose(cert), -1);
    LAPPEND_OBJ(interp, certPtr, "certificatePurpose", Tls_x509Purposes(interp, cert));

    /* Get extensions flags */
    xflags = X509_get_extension_flags(cert);
    LAPPEND_INT(interp, certPtr, "extFlags", xflags);

    /* Check if cert was issued by CA cert issuer or self signed */
    LAPPEND_BOOL(interp, certPtr, "selfIssued", xflags & EXFLAG_SI);
    LAPPEND_BOOL(interp, certPtr, "selfSigned", xflags & EXFLAG_SS);
    LAPPEND_BOOL(interp, certPtr, "isProxyCert", xflags & EXFLAG_PROXY);
    LAPPEND_BOOL(interp, certPtr, "extInvalid", xflags & EXFLAG_INVALID);
    LAPPEND_BOOL(interp, certPtr, "isCACert", X509_check_ca(cert));

    /* The Unique Ids are used to handle the possibility of reuse of subject
	and/or issuer names over time. RFC 5280 section 4.1.2.8 */
    {
	const ASN1_BIT_STRING *iuid, *suid;
	X509_get0_uids(cert, &iuid, &suid);

	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("issuerUniqueId", -1));
	if (iuid != NULL) {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewByteArrayObj((const unsigned char *)iuid->data, (Tcl_Size) iuid->length));
	} else {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
	}

	Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("subjectUniqueId", -1));
	if (suid != NULL) {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewByteArrayObj((const unsigned char *)suid->data, (Tcl_Size) suid->length));
	} else {
	    Tcl_ListObjAppendElement(interp, certPtr, Tcl_NewStringObj("", -1));
	}
    }

    /* X509 v3 Extensions - RFC 5280 section 4.1.2.9 */
    LAPPEND_INT(interp, certPtr, "extCount", X509_get_ext_count(cert));
    LAPPEND_OBJ(interp, certPtr, "extensions", Tls_x509Extensions(interp, cert));

    /* Authority Key Identifier (AKI) is the Subject Key Identifier (SKI) of
	its signer (the CA). RFC 5280 section 4.2.1.1, NID_authority_key_identifier */
    LAPPEND_OBJ(interp, certPtr, "authorityKeyIdentifier",
	Tls_x509Identifier(X509_get0_authority_key_id(cert)));

    /* Subject Key Identifier (SKI) is used to identify certificates that contain
	a particular public key. RFC 5280 section 4.2.1.2, NID_subject_key_identifier */
    LAPPEND_OBJ(interp, certPtr, "subjectKeyIdentifier",
	Tls_x509Identifier(X509_get0_subject_key_id(cert)));

    /* Key usage extension defines the purpose (e.g., encipherment, signature, certificate
	signing) of the key in the certificate. RFC 5280 section 4.2.1.3, NID_key_usage */
    LAPPEND_OBJ(interp, certPtr, "keyUsage", Tls_x509KeyUsage(interp, cert, xflags));

    /* Certificate Policies - indicates the issuing CA considers its issuerDomainPolicy
	equivalent to the subject CA's subjectDomainPolicy. RFC 5280 section 4.2.1.4, NID_certificate_policies */
    if (xflags & EXFLAG_INVALID_POLICY) {
	/* Reject cert */
    }

    /* Policy Mappings - RFC 5280 section 4.2.1.5, NID_policy_mappings */

    /* Subject Alternative Name (SAN) contains additional URLs, DNS names, or IP
	addresses bound to certificate. RFC 5280 section 4.2.1.6, NID_subject_alt_name */
    LAPPEND_OBJ(interp, certPtr, "subjectAltName", Tls_x509Names(interp, cert, NID_subject_alt_name, bio));

    /* Issuer Alternative Name is used to associate Internet style identities
	with the certificate issuer. RFC 5280 section 4.2.1.7, NID_issuer_alt_name */
    LAPPEND_OBJ(interp, certPtr, "issuerAltName", Tls_x509Names(interp, cert, NID_issuer_alt_name, bio));

    /* Subject Directory Attributes provides identification attributes (e.g., nationality)
	of the subject. RFC 5280 section 4.2.1.8 (subjectDirectoryAttributes) */

    /* Basic Constraints identifies whether the subject of the cert is a CA and
	the max depth of valid cert paths for this cert. RFC 5280 section 4.2.1.9, NID_basic_constraints */
    if (!(xflags & EXFLAG_PROXY)) {
	LAPPEND_LONG(interp, certPtr, "pathLen", X509_get_pathlen(cert));
    } else {
	LAPPEND_LONG(interp, certPtr, "pathLen", X509_get_proxy_pathlen(cert));
    }
    LAPPEND_BOOL(interp, certPtr, "basicConstraintsCA", xflags & EXFLAG_CA);

    /* Name Constraints is only used in CA certs to indicate the name space for
	all subject names in subsequent certificates in a certification path
	MUST be located. RFC 5280 section 4.2.1.10, NID_name_constraints */

    /* Policy Constraints is only used in CA certs to limit the length of a
	cert chain for that CA. RFC 5280 section 4.2.1.11, NID_policy_constraints */

    /* Extended Key Usage indicates the purposes the certified public key may be
	used, beyond the basic purposes. RFC 5280 section 4.2.1.12, NID_ext_key_usage */
    LAPPEND_OBJ(interp, certPtr, "extendedKeyUsage", Tls_x509ExtKeyUsage(interp, cert, xflags));

    /* CRL Distribution Points identifies where CRL information can be obtained.
	RFC 5280 section 4.2.1.13*/
    LAPPEND_OBJ(interp, certPtr, "crlDistributionPoints", Tls_x509CrlDp(interp, cert));

    /* Freshest CRL extension */
    if (xflags & EXFLAG_FRESHEST) {
    }

    /* Authority Information Access indicates how to access info and services
	for the certificate issuer. RFC 5280 section 4.2.2.1, NID_info_access */

    /* Get On-line Certificate Status Protocol (OSCP) Responders URL */
    LAPPEND_OBJ(interp, certPtr, "ocspResponders", Tls_x509Oscp(interp, cert));

    /* Get Certificate Authority (CA) Issuers URL */
    LAPPEND_OBJ(interp, certPtr, "caIssuers", Tls_x509CaIssuers(interp, cert));

    /* Subject Information Access - RFC 5280 section 4.2.2.2, NID_sinfo_access */

    /* Certificate Alias. If uses a PKCS#12 structure, alias will reflect the
	friendlyName attribute (RFC 2985). */
    {
	len = 0;
        unsigned char *string = X509_alias_get0(cert, &len);
	LAPPEND_STR(interp, certPtr, "alias", (char *) string, (Tcl_Size) len);
	string = X509_keyid_get0 (cert, &len);
	LAPPEND_STR(interp, certPtr, "keyId", (char *) string, (Tcl_Size) len);
    }

    /* Certificate and dump all data */
    {
	char certStr[CERT_STR_SIZE];

	/* Get certificate */
	len = BIO_to_Buffer(PEM_write_bio_X509(bio, cert), bio, certStr, CERT_STR_SIZE);
	LAPPEND_STR(interp, certPtr, "certificate", certStr, (Tcl_Size) len);

	/* Get all cert info */
	len = BIO_to_Buffer(X509_print_ex(bio, cert, flags, 0), bio, certStr, CERT_STR_SIZE);
	LAPPEND_STR(interp, certPtr, "all", certStr, (Tcl_Size) len);
    }

    BIO_free(bio);
    return certPtr;
}
