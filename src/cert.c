/**
 * @file cert.c  TLS Certificate
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include "test.h"


/*
 * Dummy certificates for testing.
 */


/**
 * X509/PEM certificate with ECDSA keypair
 *
 *  $ openssl ecparam -out ec_key.pem -name prime256v1 -genkey
 *  $ openssl req -new -key ec_key.pem -x509 -nodes -days 3650 -out cert.pem
 *
 *
 * NOTE: This is the same certificate as ./data/server-ecdsa.pem
 */
const char test_certificate_ecdsa[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIB/zCCAaWgAwIBAgIJAOM89Ziwo6HsMAoGCCqGSM49BAMCMFwxCzAJBgNVBAYT\r\n"
"AkRFMQ8wDQYDVQQIDAZSZXRlc3QxDzANBgNVBAoMBlJldGVzdDEPMA0GA1UEAwwG\r\n"
"cmV0ZXN0MRowGAYJKoZIhvcNAQkBFgtyZUB0ZXN0LmNvbTAeFw0xNjExMTEyMTQ1\r\n"
"NDdaFw0yNjExMDkyMTQ1NDdaMFwxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZSZXRl\r\n"
"c3QxDzANBgNVBAoMBlJldGVzdDEPMA0GA1UEAwwGcmV0ZXN0MRowGAYJKoZIhvcN\r\n"
"AQkBFgtyZUB0ZXN0LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBN9PbWr\r\n"
"n1jFQszb3d7Ahhu+P07nEQsH2uWbuVI/tuAStTWv5FOGrrK1Mkc8D8vaiHJSAI+Y\r\n"
"arsGUcpXvbyf6ZajUDBOMB0GA1UdDgQWBBQH/YADwfvE31Huriy3dwrSszHHQjAf\r\n"
"BgNVHSMEGDAWgBQH/YADwfvE31Huriy3dwrSszHHQjAMBgNVHRMEBTADAQH/MAoG\r\n"
"CCqGSM49BAMCA0gAMEUCIAlRWLW8qA4hlX2ikv+odJe/z2cWeIGcHNUsAaQhCw6s\r\n"
"AiEA4wvqDaBH7urPrCKPITOdeI7eL95RR3KIGFHoP71lrjk=\r\n"
"-----END CERTIFICATE-----\r\n"
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIPcsRIqjUcYgeDLtL0Nm69R5pUZ9Hhb7/HZHH5vwAiCgoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEE309taufWMVCzNvd3sCGG74/TucRCwfa5Zu5Uj+24BK1Na/kU4au\r\n"
"srUyRzwPy9qIclIAj5hquwZRyle9vJ/plg==\r\n"
"-----END EC PRIVATE KEY-----\r\n"
	;
