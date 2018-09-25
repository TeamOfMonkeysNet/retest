/**
 * @file rtmp.c RTMP Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include "test.h"


#define DEBUG_MODULE "rtmp"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


/*
 * TODO:
 *
 * - add testcase for RTMP publish
 *
 */


#define WINDOW_ACK_SIZE 2500000


#define NUM_MEDIA_PACKETS 5


/*
 * Various complete RTMP packets
 */

static const uint8_t rtmp_was[] = {
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x05,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x25, 0xa0
};

	/*
	 * ffplay rtmp://184.72.239.149/vod/mp4:bigbuckbunny_450.mp4
	 */
static const uint8_t rtmp_audio_data[] = {
	0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x08,
	0x01, 0x00, 0x00, 0x00,

	0xaf, 0x00, 0x11, 0x90, 0x08, 0xc4, 0x00, 0x00,
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00
};

static const uint8_t rtmp_video_data[] = {
	0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x09,
	0x01, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x01
};

#if 0
static const uint8_t rtmp_ping_request[] = {
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x04,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
	0x50, 0x2e
};
#endif

/*
 * Helper functions
 */


static struct mbuf *mbuf_packet(const uint8_t *pkt, size_t len)
{
	struct mbuf *mb;

	mb = mbuf_alloc(len);
	if (!mb)
		return NULL;

	(void)mbuf_write_mem(mb, pkt, len);

	mb->pos = 0;

	return mb;
}


#if 0
static int test_rtmp_decode_audio(void)
{

#define HDR_SIZE 12

	struct rtmp_header hdr;
	struct mbuf *mb;
	int err;

	mb = mbuf_packet(rtmp_audio_data, sizeof(rtmp_audio_data));
	if (!mb)
		return ENOMEM;

	err = rtmp_header_decode(&hdr, mb);
	TEST_ERR(err);

	/* compare */
	TEST_EQUALS(0,               hdr.format);
	TEST_EQUALS(6,               hdr.chunk_id);
	TEST_EQUALS(0,               hdr.timestamp);
	/*TEST_EQUALS(0,               hdr.timestamp_delta);*/
	TEST_EQUALS(82,              hdr.length);
	TEST_EQUALS(RTMP_TYPE_AUDIO, hdr.type_id);

	TEST_MEMCMP(rtmp_audio_data + HDR_SIZE,
		    sizeof(rtmp_audio_data) - HDR_SIZE,
		    mbuf_buf(mb), mbuf_get_left(mb));

 out:
	mem_deref(mb);
	return err;
}


static int test_rtmp_decode_window_ack_size(void)
{
	struct rtmp_header hdr;
	struct mbuf *mb;
	uint32_t value;
	int err;

	mb = mbuf_packet(rtmp_was, sizeof(rtmp_was));
	if (!mb)
		return ENOMEM;

	err = rtmp_header_decode(&hdr, mb);
	TEST_ERR(err);

	/* compare */
	TEST_EQUALS(0,                         hdr.format);
	TEST_EQUALS(2,                         hdr.chunk_id);
	TEST_EQUALS(0,                         hdr.timestamp);
	TEST_EQUALS(4,                         hdr.length);
	TEST_EQUALS(RTMP_TYPE_WINDOW_ACK_SIZE, hdr.type_id);
	TEST_EQUALS(0,                         hdr.stream_id);

	TEST_EQUALS(4, mbuf_get_left(mb));
	value = ntohl(mbuf_read_u32(mb));

	TEST_EQUALS(2500000, value);

 out:
	mem_deref(mb);
	return err;
}


static int test_rtmp_decode_ping_request(void)
{
	struct rtmp_header hdr;
	struct mbuf *mb;
	const void *p;
	uint16_t value;
	int err;

	mb = mbuf_packet(rtmp_ping_request, sizeof(rtmp_ping_request));
	if (!mb)
		return ENOMEM;

	err = rtmp_header_decode(&hdr, mb);
	TEST_ERR(err);

	/* compare */
	TEST_EQUALS(0,                          hdr.format);
	TEST_EQUALS(2,                          hdr.chunk_id);
	TEST_EQUALS(0,                          hdr.timestamp);
	TEST_EQUALS(6,                          hdr.length);
	TEST_EQUALS(RTMP_TYPE_USER_CONTROL_MSG, hdr.type_id);
	TEST_EQUALS(0,                          hdr.stream_id);

	TEST_EQUALS(6, mbuf_get_left(mb));
	p = mbuf_buf(mb);
	value = ntohs( *(uint16_t *)p );

	TEST_EQUALS(6, value);  /* Ping Request */

 out:
	mem_deref(mb);
	return err;
}
#endif


struct dechunk_test {
	unsigned n_msg;
	struct rtmp_header hdrv[128];
};


static int dechunk_handler(const struct rtmp_header *hdr,
			   struct mbuf *mb, void *arg)
{
	struct dechunk_test *dctest = arg;

	dctest->hdrv[dctest->n_msg] = *hdr;

	++dctest->n_msg;

	return 0;
}


static int test_rtmp_dechunking(void)
{
	static const struct test {
		uint32_t chunk_id;
		size_t length;
		uint32_t stream_id;

		const uint8_t *pkt;
		size_t size;
	} testv[] = {
		{ 2,  4, 0, rtmp_was,        ARRAY_SIZE(rtmp_was)        },
		{ 6, 82, 1, rtmp_audio_data, ARRAY_SIZE(rtmp_audio_data) },
		{ 6,  4, 1, rtmp_video_data, ARRAY_SIZE(rtmp_video_data) },
	};
	struct dechunk_test dctest = {0};
	struct rtmp_dechunker *dechunk = NULL;
	struct rtmp_header *hdr;
	size_t i;
	int err;

	err = rtmp_dechunker_alloc(&dechunk, 128,
				   dechunk_handler, &dctest);
	TEST_ERR(err);

	for (i=0; i<ARRAY_SIZE(testv); i++) {

		const struct test *test = &testv[i];
		struct mbuf mb = {
			.pos  = 0,
			.end  = test->size,
			.size = test->size,
			.buf  = (void *)test->pkt
		};

		err = rtmp_dechunker_receive(dechunk, &mb);
		if (err)
			goto out;
	}

	TEST_EQUALS(ARRAY_SIZE(testv), dctest.n_msg);

	hdr = &dctest.hdrv[0];

	TEST_EQUALS(0,    hdr->format);
	TEST_EQUALS(2,    hdr->chunk_id);
	TEST_EQUALS(0,    hdr->timestamp);
	TEST_EQUALS(0,    hdr->timestamp_delta);
	TEST_EQUALS(4,    hdr->length);
	TEST_EQUALS(5,    hdr->type_id);
	TEST_EQUALS(0,    hdr->stream_id);

	hdr = &dctest.hdrv[1];

	TEST_EQUALS(0,    hdr->format);
	TEST_EQUALS(6,    hdr->chunk_id);
	TEST_EQUALS(0,    hdr->timestamp);
	TEST_EQUALS(0,    hdr->timestamp_delta);
	TEST_EQUALS(82,   hdr->length);
	TEST_EQUALS(8,    hdr->type_id);
	TEST_EQUALS(1,    hdr->stream_id);

	hdr = &dctest.hdrv[2];

	TEST_EQUALS(0,    hdr->format);
	TEST_EQUALS(6,    hdr->chunk_id);
	TEST_EQUALS(0,    hdr->timestamp);
	TEST_EQUALS(0,    hdr->timestamp_delta);
	TEST_EQUALS(4,    hdr->length);
	TEST_EQUALS(9,    hdr->type_id);
	TEST_EQUALS(1,    hdr->stream_id);

 out:
	mem_deref(dechunk);

	return err;
}


#define MAX_CHUNK_SIZE 2
static int test_rtmp_dechunking2(void)
{
	static const uint8_t pkt[] = {

		/* Packet 1 (Type 0) */
		0x06,

		0x00, 0x03, 0xe8,     0x00, 0x00, 0x04,     0x08,
		0x90, 0x01, 0x00, 0x00,

		0xff, 0xff,

		/* Packet 2 (Type 3) */
		0xc6,

		0xff, 0xff,

		/* ----- ----- ----- ----- ----- ----- ----- */

		/* Packet 3 (Type 1) */
		0x46,

		0x00, 0x00, 0x14,     0x00, 0x00, 0x02,     0x08,

		0xff, 0xff,

		/* Packet 4 (Type 2) */
		0x86,

		0x00, 0x00, 0x14,

		0xff, 0xff,
	};
	struct dechunk_test dctest = {0};
	struct rtmp_dechunker *dechunk = NULL;
	int err;

	struct mbuf mb = {
		.pos  = 0,
		.end = ARRAY_SIZE(pkt),
		.size = ARRAY_SIZE(pkt),
		.buf  = (void *)pkt
	};

	struct rtmp_header *hdr;

	re_printf("--- test dechunk ---\n");

	err = rtmp_dechunker_alloc(&dechunk, MAX_CHUNK_SIZE,
				   dechunk_handler, &dctest);
	TEST_ERR(err);

	while (mbuf_get_left(&mb)) {

		err = rtmp_dechunker_receive(dechunk, &mb);
		if (err)
			goto out;
	}

#if 1
	re_printf("%H\n", rtmp_dechunker_debug, dechunk);
#endif

	TEST_EQUALS(3, dctest.n_msg);

	hdr = &dctest.hdrv[0];
	TEST_EQUALS(0,    hdr->format);
	TEST_EQUALS(6,    hdr->chunk_id);
	TEST_EQUALS(1000, hdr->timestamp);
	TEST_EQUALS(0,    hdr->timestamp_delta);
	TEST_EQUALS(4,    hdr->length);
	TEST_EQUALS(8,    hdr->type_id);
	TEST_EQUALS(400,  hdr->stream_id);

	hdr = &dctest.hdrv[1];
	TEST_EQUALS(1,    hdr->format);
	TEST_EQUALS(6,    hdr->chunk_id);
	TEST_EQUALS(1020, hdr->timestamp);
	TEST_EQUALS(20,   hdr->timestamp_delta);
	TEST_EQUALS(2,    hdr->length);
	TEST_EQUALS(8,    hdr->type_id);
	TEST_EQUALS(400,  hdr->stream_id);

	hdr = &dctest.hdrv[2];
	TEST_EQUALS(2,    hdr->format);
	TEST_EQUALS(6,    hdr->chunk_id);
	TEST_EQUALS(1040, hdr->timestamp);
	TEST_EQUALS(20,   hdr->timestamp_delta);
	TEST_EQUALS(2,    hdr->length);
	TEST_EQUALS(8,    hdr->type_id);
	TEST_EQUALS(400,  hdr->stream_id);

 out:
	mem_deref(dechunk);

	return err;
}


static const uint8_t amf_connect[] = {

	/* string */
	0x02,
	0x00, 0x07,
	0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,

	/* number */
	0x00,
	0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	/* object */
	0x03,

	/* app:vod */
	0x00, 0x03,
	0x61, 0x70, 0x70,
	0x02,
	0x00, 0x03,
	0x76, 0x6f, 0x64,

	/* flashVer */
	0x00, 0x08,
	0x66, 0x6c, 0x61, 0x73, 0x68, 0x56, 0x65, 0x72,
	0x02,
	0x00, 0x0d,
	0x4c, 0x4e, 0x58, 0x20, 0x39, 0x2c, 0x30, 0x2c,
	0x31, 0x32, 0x34, 0x2c, 0x32,

	/* tcUrl */
	0x00, 0x05,
	0x74, 0x63, 0x55, 0x72, 0x6c,
	0x02, 0x00, 0x1e,
	0x72, 0x74, 0x6d, 0x70, 0x3a, 0x2f, 0x2f, 0x31, 0x38, 0x34,
	0x2e, 0x37, 0x32, 0x2e, 0x32, 0x33, 0x39, 0x2e, 0x31, 0x34,
	0x39, 0x3a, 0x31, 0x39, 0x33, 0x35, 0x2f, 0x76, 0x6f, 0x64,

	/* fpad */
	0x00, 0x04,
	0x66, 0x70, 0x61, 0x64,
	0x01,
	0x00,

	/* capabilities */
	0x00, 0x0c,
	0x63, 0x61, 0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73,
	0x00,
	0x40, 0x2e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	/* audioCodecs */
	0x00, 0x0b,
	0x61, 0x75, 0x64, 0x69, 0x6f, 0x43, 0x6f, 0x64, 0x65, 0x63, 0x73,
	0x00,
	0x40, 0xaf, 0xce, 0x00, 0x00, 0x00, 0x00, 0x00,

	/* videoCodecs */
	0x00, 0x0b,
	0x76, 0x69, 0x64, 0x65, 0x6f, 0x43, 0x6f, 0x64, 0x65, 0x63, 0x73,
	0x00,
	0x40, 0x6f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,

	/* videoFunction */
	0x00, 0x0d,
	0x76, 0x69, 0x64, 0x65, 0x6f, 0x46, 0x75, 0x6e,
	0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x00,
	0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	/* object end */
	0x00, 0x00, 0x09
};


static const uint8_t amf_result[] = {
	0x02, 0x00, 0x07, 0x5f,
	0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x00, 0x3f,
	0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	0x00, 0x06, 0x66, 0x6d, 0x73, 0x56, 0x65, 0x72,
	0x02, 0x00, 0x0e, 0x46, 0x4d, 0x53, 0x2f, 0x33,
	0x2c, 0x35, 0x2c, 0x37, 0x2c, 0x37, 0x30, 0x30,
	0x39, 0x00, 0x0c, 0x63, 0x61, 0x70, 0x61, 0x62,
	0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x00,
	0x40, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x00, 0x3f,
	0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x09, 0x03, 0x00, 0x05, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x02, 0x00, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x00, 0x04, 0x63, 0x6f, 0x64,
	0x65, 0x02, 0x00, 0x1d, 0x4e, 0x65, 0x74, 0x43,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x2e, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x00, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x02, 0x00,
	0x15, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x20, 0x73, 0x75, 0x63, 0x63,
	0x65, 0x65, 0x64, 0x65, 0x64, 0x2e, 0x00, 0x04,
	0x64, 0x61, 0x74, 0x61, 0x08, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x02, 0x00, 0x0a, 0x33, 0x2c, 0x35,
	0x2c, 0x37, 0x2c, 0x37, 0x30, 0x30, 0x39, 0x00,
	0x00, 0x09, 0x00, 0x08, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x69, 0x64, 0x00, 0x41, 0xc2, 0xc9,
	0xb8, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x6f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x45, 0x6e, 0x63,
	0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x09
};


static const uint8_t amf_connect_result[] = {
	0x02, 0x00, 0x07, 0x5f,
	0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x00, 0x3f,
	0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	0x00, 0x06, 0x66, 0x6d, 0x73, 0x56, 0x65, 0x72,
	0x02, 0x00, 0x0e, 0x46, 0x4d, 0x53, 0x2f, 0x33,
	0x2c, 0x35, 0x2c, 0x37, 0x2c, 0x37, 0x30, 0x30,
	0x39, 0x00, 0x0c, 0x63, 0x61, 0x70, 0x61, 0x62,
	0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x00,
	0x40, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x00, 0x3f,
	0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x09, 0x03, 0x00, 0x05, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x02, 0x00, 0x06, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x00, 0x04, 0x63, 0x6f, 0x64,
	0x65, 0x02, 0x00, 0x1d, 0x4e, 0x65, 0x74, 0x43,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x2e, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x00, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72,
	0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x02, 0x00,
	0x15, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x20, 0x73, 0x75, 0x63, 0x63,
	0x65, 0x65, 0x64, 0x65, 0x64, 0x2e, 0x00, 0x04,
	0x64, 0x61, 0x74, 0x61, 0x08, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x02, 0x00, 0x0a, 0x33, 0x2c, 0x35,
	0x2c, 0x37, 0x2c, 0x37, 0x30, 0x30, 0x39, 0x00,
	0x00, 0x09, 0x00, 0x08, 0x63, 0x6c, 0x69, 0x65,
	0x6e, 0x74, 0x69, 0x64, 0x00, 0x41, 0xc5, 0xe6,
	0x21, 0x42, 0x80, 0x00, 0x00, 0x00, 0x0e, 0x6f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x45, 0x6e, 0x63,
	0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x09
};

static const uint8_t amf_createstream[] = {
	0x02, 0x00, 0x0c, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x05
};

static const uint8_t amf_publish[] = {
	0x02, 0x00, 0x07, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x00, 0x40,
	0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
	0x02, 0x00, 0x10, 0x76, 0x79, 0x62, 0x51, 0x4e,
	0x46, 0x65, 0x37, 0x59, 0x72, 0x62, 0x30, 0x4e,
	0x33, 0x4f, 0x51, 0x02, 0x00, 0x04, 0x6c, 0x69,
	0x76, 0x65
};


static const uint8_t amf_onmetadata[] = {
	0x02, 0x00, 0x0a, 0x6f,
	0x6e, 0x4d, 0x65, 0x74, 0x61, 0x44, 0x61, 0x74,
	0x61, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
	0x74, 0x72, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x66,
	0x6f, 0x0a, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00,
	0x08, 0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67,
	0x65, 0x02, 0x00, 0x03, 0x75, 0x6e, 0x64, 0x00,
	0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x63, 0x61,
	0x6c, 0x65, 0x00, 0x40, 0xce, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x6c, 0x65, 0x6e,
	0x67, 0x74, 0x68, 0x00, 0x41, 0x62, 0x97, 0xc0,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x73, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x0a,
	0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x0a, 0x73,
	0x61, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x79, 0x70,
	0x65, 0x02, 0x00, 0x04, 0x61, 0x76, 0x63, 0x31,
	0x00, 0x00, 0x09, 0x00, 0x00, 0x09, 0x03, 0x00,
	0x08, 0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67,
	0x65, 0x02, 0x00, 0x03, 0x75, 0x6e, 0x64, 0x00,
	0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x63, 0x61,
	0x6c, 0x65, 0x00, 0x40, 0xe7, 0x70, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x6c, 0x65, 0x6e,
	0x67, 0x74, 0x68, 0x00, 0x41, 0x7d, 0x07, 0xa0,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x73, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x64, 0x65, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x0a,
	0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x0a, 0x73,
	0x61, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x79, 0x70,
	0x65, 0x02, 0x00, 0x04, 0x6d, 0x70, 0x34, 0x61,
	0x00, 0x00, 0x09, 0x00, 0x00, 0x09, 0x00, 0x0d,
	0x61, 0x75, 0x64, 0x69, 0x6f, 0x63, 0x68, 0x61,
	0x6e, 0x6e, 0x65, 0x6c, 0x73, 0x00, 0x40, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
	0x61, 0x75, 0x64, 0x69, 0x6f, 0x73, 0x61, 0x6d,
	0x70, 0x6c, 0x65, 0x72, 0x61, 0x74, 0x65, 0x00,
	0x40, 0xe7, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x0e, 0x76, 0x69, 0x64, 0x65, 0x6f, 0x66,
	0x72, 0x61, 0x6d, 0x65, 0x72, 0x61, 0x74, 0x65,
	0x00, 0x40, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x06, 0x61, 0x61, 0x63, 0x61, 0x6f,
	0x74, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x08, 0x61, 0x76, 0x63, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x00, 0x40, 0x35, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x61,
	0x76, 0x63, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c,
	0x65, 0x00, 0x40, 0x50, 0x80, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0c, 0x61, 0x75, 0x64, 0x69,
	0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x69, 0x64,
	0x02, 0x00, 0x04, 0x6d, 0x70, 0x34, 0x61, 0x00,
	0x0c, 0x76, 0x69, 0x64, 0x65, 0x6f, 0x63, 0x6f,
	0x64, 0x65, 0x63, 0x69, 0x64, 0x02, 0x00, 0x04,
	0x61, 0x76, 0x63, 0x31, 0x00, 0x05, 0x77, 0x69,
	0x64, 0x74, 0x68, 0x00, 0x40, 0x80, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x68, 0x65,
	0x69, 0x67, 0x68, 0x74, 0x00, 0x40, 0x72, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x66,
	0x72, 0x61, 0x6d, 0x65, 0x57, 0x69, 0x64, 0x74,
	0x68, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0b, 0x66, 0x72, 0x61, 0x6d,
	0x65, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x00,
	0x40, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61,
	0x79, 0x57, 0x69, 0x64, 0x74, 0x68, 0x00, 0x40,
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0d, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79,
	0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x00, 0x40,
	0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x09, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x72, 0x61,
	0x74, 0x65, 0x00, 0x40, 0x3e, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0c, 0x6d, 0x6f, 0x6f,
	0x76, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f,
	0x6e, 0x00, 0x41, 0x8b, 0xd9, 0xf3, 0x90, 0x00,
	0x00, 0x00, 0x00, 0x08, 0x64, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x00, 0x40, 0x83, 0xd5,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x09
};


static int test_rtmp_amf_encode_connect(void)
{
	struct mbuf *mb = NULL;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err  = rtmp_amf_encode_string(mb, "connect");
	err |= rtmp_amf_encode_number(mb, 1.0);

	err |= rtmp_amf_encode_object(mb, RTMP_AMF_TYPE_OBJECT, 8,
		RTMP_AMF_TYPE_STRING, "app", "vod",
		RTMP_AMF_TYPE_STRING, "flashVer", "LNX 9,0,124,2",
		RTMP_AMF_TYPE_STRING, "tcUrl","rtmp://184.72.239.149:1935/vod",
		RTMP_AMF_TYPE_BOOLEAN, "fpad", false,
		RTMP_AMF_TYPE_NUMBER, "capabilities", 15.0,
		RTMP_AMF_TYPE_NUMBER, "audioCodecs", 4071.0,
		RTMP_AMF_TYPE_NUMBER, "videoCodecs", 252.0,
		RTMP_AMF_TYPE_NUMBER, "videoFunction", 1.0);
	TEST_ERR(err);

	TEST_MEMCMP(amf_connect, sizeof(amf_connect), mb->buf, mb->end);

 out:
	mem_deref(mb);

	return err;
}


static int test_rtmp_amf_encode_connect_result(void)
{
	struct mbuf *mb = NULL;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err  = rtmp_amf_encode_string(mb, "_result");
	err |= rtmp_amf_encode_number(mb, 1);

	err |= rtmp_amf_encode_object(mb, RTMP_AMF_TYPE_OBJECT, 3,
			     RTMP_AMF_TYPE_STRING, "fmsVer", "FMS/3,5,7,7009",
			     RTMP_AMF_TYPE_NUMBER, "capabilities", 31.0,
			     RTMP_AMF_TYPE_NUMBER, "mode", 1.0);
	TEST_ERR(err);

	err |= rtmp_amf_encode_object(mb, RTMP_AMF_TYPE_OBJECT, 6,
	      RTMP_AMF_TYPE_STRING, "level", "status",
	      RTMP_AMF_TYPE_STRING, "code", "NetConnection.Connect.Success",
	      RTMP_AMF_TYPE_STRING, "description", "Connection succeeded.",
	      RTMP_AMF_TYPE_ECMA_ARRAY, "data", 1,
		      RTMP_AMF_TYPE_STRING, "version", "3,5,7,7009",
	      RTMP_AMF_TYPE_NUMBER, "clientid", 734806661.0,
	      RTMP_AMF_TYPE_NUMBER, "objectEncoding", 0.0);
	TEST_ERR(err);

	TEST_MEMCMP(amf_connect_result, sizeof(amf_connect_result),
		    mb->buf, mb->end);

 out:
	mem_deref(mb);

	return err;
}


static int test_rtmp_amf_encode_createstream(void)
{
	struct mbuf *mb = 0;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err  = rtmp_amf_encode_string(mb, "createStream");
	err |= rtmp_amf_encode_number(mb, 2);
	err |= rtmp_amf_encode_null(mb);

	TEST_MEMCMP(amf_createstream, sizeof(amf_createstream),
		    mb->buf, mb->end);

 out:
	mem_deref(mb);

	return err;
}


static int test_rtmp_amf_encode_publish(void)
{
	struct mbuf *mb = NULL;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err  = rtmp_amf_encode_string(mb, "publish");
	err |= rtmp_amf_encode_number(mb, 5);
	err |= rtmp_amf_encode_null(mb);
	err |= rtmp_amf_encode_string(mb, "vybQNFe7Yrb0N3OQ");
	err |= rtmp_amf_encode_string(mb, "live");

	TEST_MEMCMP(amf_publish, sizeof(amf_publish), mb->buf, mb->end);

 out:
	mem_deref(mb);

	return err;
}


static const uint8_t amf_strictarray[] = {

	0x0a,
	0x00, 0x00, 0x00, 0x02,  /* length (2 entries) */

	/* index 0 -- Number */
	0x00,
	0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	/* index 1 -- Strict Array */
	0x0a,
	0x00, 0x00, 0x00, 0x02,

	  /* Null */
	  0x05,

	  /* String */
	  0x02,
	  0x00, 0x03,
	  0x61, 0x62, 0x63,
};


static int test_rtmp_amf_encode_strictarray(void)
{
	struct mbuf *mb = NULL;
	int err;

	mb = mbuf_alloc(512);
	if (!mb)
		return ENOMEM;

	err  = rtmp_amf_encode_object(mb,
				      RTMP_AMF_TYPE_STRICT_ARRAY, 2,
				          RTMP_AMF_TYPE_NUMBER, 1.0,
				          RTMP_AMF_TYPE_STRICT_ARRAY, 2,
				              RTMP_AMF_TYPE_NULL,
				              RTMP_AMF_TYPE_STRING, "abc"
				      );
	TEST_ERR(err);

	TEST_MEMCMP(amf_strictarray, sizeof(amf_strictarray),
		    mb->buf, mb->end);

 out:
	mem_deref(mb);

	return err;
}


static int test_rtmp_amf_decode(const uint8_t *buf, size_t len,
				size_t count, size_t count_all,
				const char *command_name)
{
	struct rtmp_amf_message *msg = NULL;
	struct mbuf *mb = NULL;
	struct odict *dict;
	const char *name;
	bool ret;
	int err;

	mb = mbuf_packet(buf, len);
	if (!mb)
		return ENOMEM;

	err = rtmp_amf_decode(&msg, mb);
	if (err)
		goto out;

	dict = rtmp_amf_message_dict(msg);

	TEST_EQUALS(count,     odict_count(dict, false));
	TEST_EQUALS(count_all, odict_count(dict, true));

	name = rtmp_amf_message_string(msg, 0);
	TEST_STRCMP(command_name, str_len(command_name),
		    name, str_len(name));

	/* should not exist */
	ret = rtmp_amf_message_get_number(msg, NULL, 0);
	TEST_ASSERT(!ret);

	/* todo: verify decoded object */

 out:
	mem_deref(msg);
	mem_deref(mb);

	return err;
}


struct rtmp_endpoint {
	struct rtmp_endpoint *other;
	struct rtmp_conn *conn;
	struct rtmp_stream *stream;
	struct tcp_sock *ts;     /* server only */
	const char *tag;
	bool is_client;
	unsigned n_estab;
	unsigned n_cmd;
	unsigned n_close;
	unsigned n_ready;
	unsigned n_play;
	unsigned n_audio;
	unsigned n_video;
	int err;

	struct tcp_helper *th;
	size_t packet_count;
	bool fuzzing;
};


static const uint8_t fake_audio_packet[6] = {
	0x5b, 0xb2, 0xfb, 0x11, 0x46, 0xe9
};

static const uint8_t fake_video_packet[8] = {
	0xcb, 0x9c, 0xb5, 0x60, 0x7f, 0xe9, 0xbd, 0xe1
};
static const char *fake_stream_name = "sample.mp4";


static void endpoint_terminate(struct rtmp_endpoint *ep, int err)
{
	if (err) {
		DEBUG_WARNING("[ %s ] terminate: %m\n", ep->tag, err);
	}

	ep->err = err;
	re_cancel();
}


/* criteria for test to be finished */
static bool is_finished(const struct rtmp_endpoint *ep)
{
	if (ep->is_client) {

		return ep->n_ready > 0 &&
			ep->n_audio >= NUM_MEDIA_PACKETS &&
			ep->n_video >= NUM_MEDIA_PACKETS;
	}
	else {
		return ep->n_play > 0;
	}

}


static bool endpoints_are_finished(const struct rtmp_endpoint *ep)
{
	return is_finished(ep) && is_finished(ep->other);
}


#if 0
static void stream_ready_handler(void *arg)
{
	struct rtmp_endpoint *ep = arg;

	++ep->n_ready;

#if 0
	/* Test complete ? */
	if (endpoints_are_finished(ep)) {
		re_cancel();
	}
#endif

}
#endif


static void stream_command_handler(const struct rtmp_amf_message *msg,
				   void *arg)
{
}


static void stream_control_handler(enum rtmp_event_type event, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	(void)ep;
}


static void audio_handler(uint32_t timestamp,
			  const uint8_t *pld, size_t len, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err = 0;

	re_printf("recv audio pkt\n");

	TEST_EQUALS(ep->n_audio, timestamp);

	++ep->n_audio;

	TEST_MEMCMP(fake_audio_packet, sizeof(fake_audio_packet), pld, len);

	/* Test complete ? */
	if (endpoints_are_finished(ep)) {
		re_cancel();
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}
#define TS_OFFSET 100

static void video_handler(uint32_t timestamp,
			  const uint8_t *pld, size_t len, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err = 0;

	TEST_EQUALS(TS_OFFSET + ep->n_video, timestamp);

	++ep->n_video;

	TEST_MEMCMP(fake_video_packet, sizeof(fake_video_packet), pld, len);

	/* Test complete ? */
	if (endpoints_are_finished(ep)) {
		re_cancel();
	}

 out:
	if (err)
		endpoint_terminate(ep, err);
}


static void stream_data_handler(const struct rtmp_amf_message *msg, void *arg)
{
}


static void stream_create_resp_handler(const struct rtmp_amf_message *msg,
				       void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err;

	re_printf("create stream resp: %H\n",
		  odict_debug, rtmp_amf_message_dict(msg));

	++ep->n_ready;

	err = rtmp_play(ep->stream, fake_stream_name);
	if (err)
		goto error;

	return;

 error:
	endpoint_terminate(ep, err);
}


static void estab_handler(void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err = 0;

	DEBUG_INFO("[%s] Established\n", ep->tag);

	++ep->n_estab;

	if (ep->is_client) {

		err = rtmp_stream_create(&ep->stream, ep->conn,
					 stream_create_resp_handler,
					 stream_command_handler,
					 stream_control_handler,
					 audio_handler,
					 video_handler, stream_data_handler,
					 ep);
		if (err)
			goto error;
	}

	return;

 error:
	endpoint_terminate(ep, err);
}


/* Server */
static int server_send_reply(struct rtmp_conn *conn,
			     const struct rtmp_amf_message *req)
{
	const char *code = "NetConnection.Connect.Success";
	const char *descr = "Connection succeeded.";
	int err;

	err = rtmp_amf_reply(conn, 0, true, req,
				2,

		RTMP_AMF_TYPE_OBJECT, 3,
			RTMP_AMF_TYPE_STRING, "fmsVer",       "FMS/3,5,7,7009",
			RTMP_AMF_TYPE_NUMBER, "capabilities", 31.0,
			RTMP_AMF_TYPE_NUMBER, "mode",         1.0,

		RTMP_AMF_TYPE_OBJECT, 6,
			RTMP_AMF_TYPE_STRING, "level",        "status",
			RTMP_AMF_TYPE_STRING, "code",         code,
			RTMP_AMF_TYPE_STRING, "description",  descr,
			RTMP_AMF_TYPE_ECMA_ARRAY,  "data",         1,
			    RTMP_AMF_TYPE_STRING, "version",      "3,5,7,7009",
			RTMP_AMF_TYPE_NUMBER, "clientid",     734806661.0,
			RTMP_AMF_TYPE_NUMBER, "objectEncoding", 0.0);

	return err;
}


static void command_handler(const struct rtmp_amf_message *msg, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	const char *name;
	int err = 0;

	name = rtmp_amf_message_string(msg, 0);

	re_printf("got command:  %s\n", name);

	++ep->n_cmd;

	if (0 == str_casecmp(name, "connect")) {

		err = rtmp_control(ep->conn, RTMP_TYPE_WINDOW_ACK_SIZE,
				   (uint32_t)WINDOW_ACK_SIZE);
		if (err)
			goto error;

		err = rtmp_control(ep->conn, RTMP_TYPE_SET_PEER_BANDWIDTH,
				   (uint32_t)WINDOW_ACK_SIZE, 2);
		if (err)
			goto error;

		/* Stream Begin */
		err = rtmp_control(ep->conn, RTMP_TYPE_USER_CONTROL_MSG,
				   RTMP_EVENT_STREAM_BEGIN,
				   RTMP_CONTROL_STREAM_ID);
		if (err)
			goto error;

		err = server_send_reply(ep->conn, msg);
		if (err) {
			re_printf("rtmp: reply failed (%m)\n", err);
			goto error;
		}
	}
	else if (0 == str_casecmp(name, "createStream")) {

		uint32_t stream_id = 42;

		err = rtmp_stream_alloc(&ep->stream, ep->conn, stream_id,
					stream_command_handler,
					stream_control_handler, audio_handler,
					video_handler, stream_data_handler,
					ep);
		if (err) {
			goto error;
		}

		err = rtmp_amf_reply(ep->conn, 0, true, msg,
					2,
				RTMP_AMF_TYPE_NULL, NULL,
				RTMP_AMF_TYPE_NUMBER, (double)stream_id);
		if (err) {
			re_printf("rtmp: reply failed (%m)\n", err);
			goto error;
		}
	}
	else if (0 == str_casecmp(name, "play")) {

		const char *stream_name;
		uint64_t tid;
		uint32_t i;

		++ep->n_play;

		if (!rtmp_amf_message_get_number(msg, &tid, 1)) {
			err = EPROTO;
			goto out;
		}
		TEST_EQUALS(0, tid);

		/* XXX: use a fixed stream name and compare */

		stream_name = rtmp_amf_message_string(msg, 3);
		TEST_STRCMP(fake_stream_name, strlen(fake_stream_name),
			    stream_name, str_len(stream_name));

		/* Send some dummy media packets to client */

		for (i=0; i<NUM_MEDIA_PACKETS; i++) {

			err = rtmp_send_audio(ep->stream, i,
					      fake_audio_packet,
					      sizeof(fake_audio_packet));
			if (err)
				goto error;

			err = rtmp_send_video(ep->stream, TS_OFFSET + i,
					      fake_video_packet,
					      sizeof(fake_video_packet));
			if (err)
				goto error;
		}
	}
	else {
		DEBUG_NOTICE("rtmp: server: command not handled (%s)\n",
			     name);
		err = EPROTO;
		goto error;
	}

	return;

 out:
 error:
	if (err)
		endpoint_terminate(ep, err);
}


static void close_handler(int err, void *arg)
{
	struct rtmp_endpoint *ep = arg;

	DEBUG_NOTICE("rtmp connection closed (%m)\n", err);

	++ep->n_close;

	endpoint_terminate(ep, err);
}


static void endpoint_destructor(void *data)
{
	struct rtmp_endpoint *ep = data;

	mem_deref(ep->conn);
	mem_deref(ep->ts);
}


static struct rtmp_endpoint *rtmp_endpoint_alloc(bool is_client)
{
	struct rtmp_endpoint *ep;

	ep = mem_zalloc(sizeof(*ep), endpoint_destructor);
	if (!ep)
		return NULL;

	ep->is_client = is_client;

	ep->tag = is_client ? "Client" : "Server";

	return ep;
}


static void apply_fuzzing(struct rtmp_endpoint *ep, struct mbuf *mb)
{
	const size_t len = mbuf_get_left(mb);
	size_t pos;
	bool flip;
	unsigned bit;

	++ep->packet_count;

	pos = rand_u16() % len;
	bit = rand_u16() % 8;

	/* percent change of corrupt packet */
	flip = ((rand_u16() % 100) < 33);

	if (flip) {
		/* flip a random bit */
		mbuf_buf(mb)[pos] ^= 1<<bit;
	}
}


static bool helper_send_handler(int *err, struct mbuf *mb, void *arg)
{
	struct rtmp_endpoint *ep = arg;

	apply_fuzzing(ep, mb);

	return false;
}


static bool helper_recv_handler(int *err, struct mbuf *mb, bool *estab,
				void *arg)
{
	struct rtmp_endpoint *ep = arg;

	apply_fuzzing(ep, mb);

	return false;
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct rtmp_endpoint *ep = arg;
	int err;

	err = rtmp_accept(&ep->conn, ep->ts, estab_handler,
			  command_handler, close_handler, ep);
	if (err)
		goto error;

	/* Enable fuzzing on the server */
	if (ep->fuzzing) {
		err = tcp_register_helper(&ep->th, rtmp_conn_tcpconn(ep->conn),
					  -1000,
					  0, helper_send_handler,
					  helper_recv_handler, ep);
		if (err)
			goto error;
	}

	return;

 error:
	if (err)
		endpoint_terminate(ep, err);
}


static int test_rtmp_client_server_conn(bool fuzzing)
{
	struct rtmp_endpoint *cli, *srv;
	struct sa srv_addr;
	char uri[256];
	int err = 0;

	cli = rtmp_endpoint_alloc(true);
	srv = rtmp_endpoint_alloc(false);
	TEST_ASSERT(cli != NULL);
	TEST_ASSERT(srv != NULL);

	cli->fuzzing = fuzzing;
	srv->fuzzing = fuzzing;

	cli->other = srv;
	srv->other = cli;

	err = sa_set_str(&srv_addr, "127.0.0.1", 0);
	TEST_ERR(err);

	err = tcp_listen(&srv->ts, &srv_addr, tcp_conn_handler, srv);
	TEST_ERR(err);

	err = tcp_local_get(srv->ts, &srv_addr);
	TEST_ERR(err);

	re_snprintf(uri, sizeof(uri), "rtmp://%J/vod/foo", &srv_addr);

	err = rtmp_connect(&cli->conn, uri, estab_handler,
			   command_handler, close_handler, cli);
	if (err)
		goto out;

	err = re_main_timeout(1000);
	if (err)
		goto out;

	if (cli->err) {
		err = cli->err;
		goto out;
	}
	if (srv->err) {
		err = srv->err;
		goto out;
	}

	TEST_EQUALS(1, cli->n_estab);
	/*TEST_EQUALS(1, srv->n_estab);*/
	TEST_EQUALS(0, cli->n_cmd);
	TEST_EQUALS(3, srv->n_cmd);
	TEST_EQUALS(0, cli->n_close);
	TEST_EQUALS(0, srv->n_close);

	TEST_EQUALS(1, cli->n_ready);
	TEST_EQUALS(0, srv->n_ready);
	TEST_EQUALS(0, cli->n_play);
	TEST_EQUALS(1, srv->n_play);

	/* play command */
	TEST_EQUALS(5, cli->n_audio);
	TEST_EQUALS(5, cli->n_video);
	TEST_EQUALS(0, srv->n_audio);
	TEST_EQUALS(0, srv->n_video);

 out:
	mem_deref(srv);
	mem_deref(cli);

	return err;
}


int test_rtmp(void)
{
	int err = 0;

#if 0
	/* Test packet decoding */
	err |= test_rtmp_decode_audio();
	err |= test_rtmp_decode_window_ack_size();
	err |= test_rtmp_decode_ping_request();
	if (err)
		return err;
#endif

	/* Test chunking */
#if 1
	err |= test_rtmp_dechunking();
#endif
	err |= test_rtmp_dechunking2();
	if (err)
		return err;

#if 1
	/* AMF Encode */
	err  = test_rtmp_amf_encode_connect();
	err |= test_rtmp_amf_encode_connect_result();
	err |= test_rtmp_amf_encode_createstream();
	err |= test_rtmp_amf_encode_publish();
	err |= test_rtmp_amf_encode_strictarray();
	if (err)
		return err;

	/* AMF Decode */
	err |= test_rtmp_amf_decode(amf_connect_result,
				    sizeof(amf_connect_result), 4, 11,
				    "_result");

	err |= test_rtmp_amf_decode(amf_connect, sizeof(amf_connect), 3, 10,
				    "connect");
	err |= test_rtmp_amf_decode(amf_result, sizeof(amf_result), 4, 11,
				    "_result");
	err |= test_rtmp_amf_decode(amf_publish,
				    sizeof(amf_publish), 5, 5,
				    "publish");
	err |= test_rtmp_amf_decode(amf_onmetadata,
				    sizeof(amf_onmetadata), 2, 26,
				    "onMetaData");
	if (err)
		return err;
#endif

#if 1
	/* Client/Server loop */
	err = test_rtmp_client_server_conn(false);
	if (err)
		return err;
#endif

	return err;
}


int test_rtmp_fuzzing(void)
{
	int err = 0, e;
	int i;

	for (i=0; i<32; i++) {

		/* Client/Server loop */
		e = test_rtmp_client_server_conn(true);

		switch (e) {

		case 0:
		case EBADMSG:
		case EINVAL:
		case ENOENT:
		case ENOSTR:
		case EOVERFLOW:
		case EPROTO:
		case ERANGE:
		case ETIMEDOUT:
		case ENOMEM:
			break;

		default:
			DEBUG_WARNING("unexpected fuzz error %d (%m)\n", e, e);
			return e;
		}
	}

	return err;
}
