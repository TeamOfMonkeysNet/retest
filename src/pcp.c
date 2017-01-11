/**
 * @file pcp.c Port Control Protocol (PCP) Testcode
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re.h>
#include <rew.h>
#include "test.h"


#define DEBUG_MODULE "pcptest"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static int test_pcp_request_loop(size_t offset)
{
	struct mbuf *mb;
	struct pcp_msg *msg = NULL;
	static const uint8_t nonce[12] = {
		0xc0, 0xff, 0xee, 0x00,
		0xc0, 0xff, 0xee, 0x00,
		0xc0, 0xff, 0xee, 0x00,
	};
	size_t i;
	int err = 0;
	const uint16_t int_port = 2000;
	static const struct {
		enum pcp_opcode opcode;
		uint32_t lifetime;
		const char *ipaddr;
	} testreqv[] = {
		{PCP_MAP,       600,    "10.0.0.20"                          },
		{PCP_MAP,       3600,   "2a02:fe0:cf12:91:226:8ff:fee1:cdf3" },
		{PCP_PEER,      600,    "46.123.65.9"                        },
		{PCP_PEER,      999999, "2a02:fe0:cf12:91:226:8ff:fee1:cdf3" },
	};

	mb = mbuf_alloc(offset + 512);
	if (!mb)
		return ENOMEM;

	for (i=0; i<ARRAY_SIZE(testreqv); i++) {

		struct sa sa;
		struct pcp_peer peer;

		err = sa_set_str(&sa, testreqv[i].ipaddr, int_port);
		if (err)
			break;

		memcpy(peer.map.nonce, nonce, sizeof(peer.map.nonce));
		peer.map.proto       = IPPROTO_UDP;
		peer.map.int_port    = int_port;
		peer.map.ext_addr    = sa;
		peer.remote_addr = sa;

		mb->pos = mb->end = offset;
		err = pcp_msg_req_encode(mb, testreqv[i].opcode,
					 testreqv[i].lifetime,
					 &sa, &peer, 0);
		if (err)
			break;

		TEST_ASSERT(mb->pos != offset);
		TEST_ASSERT(mb->end != offset);

		mb->pos = offset;
		err = pcp_msg_decode(&msg, mb);
		if (err)
			break;

		TEST_EQUALS(PCP_VERSION, msg->hdr.version);
		TEST_EQUALS(false, msg->hdr.resp);
		TEST_EQUALS(testreqv[i].opcode, msg->hdr.opcode);
		TEST_EQUALS(testreqv[i].lifetime, msg->hdr.lifetime);
		TEST_SACMP(&sa, &msg->hdr.cli_addr, SA_ADDR);

		switch (testreqv[i].opcode) {

		case PCP_MAP:
		case PCP_PEER:
			TEST_MEMCMP(nonce, sizeof(nonce),
				    msg->pld.map.nonce,
				    sizeof(msg->pld.map.nonce));
			TEST_EQUALS(IPPROTO_UDP, msg->pld.map.proto);
			TEST_EQUALS(int_port, msg->pld.map.int_port);
			break;

		default:
			break;
		}

		TEST_EQUALS(0, list_count(&msg->optionl));

		msg = mem_deref(msg);
	}

 out:
	mem_deref(msg);
	mem_deref(mb);

	return err;
}


static const uint8_t peer_request[] = {

	0x02, 0x02, 0x00, 0x00,  /*  version | opcode             */
	0x00, 0x00, 0x02, 0x58,  /*  lifetime                     */
	0x2a, 0x00, 0x14, 0x50,  /*  .                            */
	0x40, 0x0f, 0x08, 0x03,  /*  |client IP-address           */
	0x00, 0x00, 0x00, 0x00,  /*  |                            */
	0x00, 0x00, 0x10, 0x00,  /*  '                            */

	0xa9, 0x5f, 0xc9, 0xb7,  /*                               */
	0x12, 0x3b, 0xa9, 0x66,  /* nonce                         */
	0x33, 0xcd, 0xe2, 0xb9,  /*                               */

	0x11, 0x00, 0x00, 0x00,  /* protocol                      */
	0x13, 0x8c, 0x13, 0x8d,  /* internal port | external port */
	0x2a, 0x00, 0x14, 0x50,  /*  .                            */
	0x40, 0x0f, 0x08, 0x03,  /*  |external IP Address         */
	0x00, 0x00, 0x00, 0x00,  /*  |                            */
	0x00, 0x00, 0x20, 0x00,  /*  '                            */

	0x13, 0x8e, 0x00, 0x00,  /* remote peer port              */

	0x2a, 0x00, 0x14, 0x50,  /*                               */
	0x40, 0x0f, 0x08, 0x03,  /* remote peer IP-address        */
	0x00, 0x00, 0x00, 0x00,  /*                               */
	0x00, 0x00, 0x30, 0x00,  /*                               */

	0x01, 0x00, 0x00, 0x10,  /* opcode THIRD_PARTY header     */
	0x2a, 0x00, 0x14, 0x50,  /* .                             */
	0x40, 0x0f, 0x08, 0x03,  /* |internal IP address          */
	0x00, 0x00, 0x00, 0x00,  /* |                             */
	0x00, 0x00, 0x40, 0x00,  /* '                             */
};


static int test_pcp_message(void)
{
	enum pcp_opcode opcode = PCP_PEER;
	uint32_t lifetime = 600;
	static const uint8_t nonce[] = {
		0xa9, 0x5f, 0xc9, 0xb7,
		0x12, 0x3b, 0xa9, 0x66,
		0x33, 0xcd, 0xe2, 0xb9,
	};
	int proto = IPPROTO_UDP;
	struct pcp_peer peer;
	struct sa int_addr, thi_addr;
	struct mbuf *mb;
	struct pcp_msg *msg = NULL;
	enum {DUMMY_OFFSET = 64};
	int err = 0;

	memcpy(peer.map.nonce, nonce, sizeof(peer.map.nonce));
	peer.map.proto       = IPPROTO_UDP;
	peer.map.int_port    = 5004;

	err |= sa_set_str(&int_addr, "2a00:1450:400f:803::1000", 0);
	err |= sa_set_str(&peer.map.ext_addr, "2a00:1450:400f:803::2000",
			  5005);
	err |= sa_set_str(&peer.remote_addr, "2a00:1450:400f:803::3000", 5006);
	err |= sa_set_str(&thi_addr, "2a00:1450:400f:803::4000", 0);
	if (err)
		return err;

	mb = mbuf_alloc(DUMMY_OFFSET + 512);
	if (!mb)
		return ENOMEM;

	mb->pos = DUMMY_OFFSET;
	err = pcp_msg_req_encode(mb, opcode, lifetime, &int_addr, &peer,
				 1, PCP_OPTION_THIRD_PARTY, &thi_addr);
	if (err)
		goto out;

	TEST_ASSERT(mb->pos != DUMMY_OFFSET);
	TEST_ASSERT(mb->pos == mb->end);

	mb->pos = DUMMY_OFFSET;

	TEST_MEMCMP(peer_request, sizeof(peer_request),
		    mbuf_buf(mb), mbuf_get_left(mb));

	err = pcp_msg_decode(&msg, mb);
	if (err)
		goto out;

	TEST_EQUALS(PCP_VERSION, msg->hdr.version);
	TEST_EQUALS(false, msg->hdr.resp);
	TEST_EQUALS(opcode, msg->hdr.opcode);
	TEST_EQUALS(lifetime, msg->hdr.lifetime);
	TEST_SACMP(&int_addr, &msg->hdr.cli_addr, SA_ALL);

	TEST_MEMCMP(nonce, sizeof(nonce),
		    msg->pld.peer.map.nonce, sizeof(msg->pld.peer.map.nonce));
	TEST_EQUALS(proto, msg->pld.peer.map.proto);
	TEST_EQUALS(5004, msg->pld.peer.map.int_port);
	TEST_SACMP(&peer.map.ext_addr, &msg->pld.peer.map.ext_addr, SA_ALL);
	TEST_SACMP(&peer.remote_addr, &msg->pld.peer.remote_addr, SA_ALL);

 out:
	mem_deref(mb);
	mem_deref(msg);
	return err;
}


static int test_pcp_bad(void)
{
	struct pcp_msg *msg = NULL;
	struct mbuf *mb = mbuf_alloc(512);
	int err = EBADMSG;

	mb->end = 0; (void)mbuf_fill(mb, 0x00, PCP_MIN_PACKET-1); mb->pos = 0;
	if (EBADMSG != pcp_msg_decode(&msg, mb)) goto error;

	mb->end = 0; (void)mbuf_fill(mb, 0x00, PCP_MAX_PACKET+1); mb->pos = 0;
	if (EBADMSG != pcp_msg_decode(&msg, mb)) goto error;

	mb->end = 0; (void)mbuf_fill(mb, 0x00, 63); mb->pos = 0;
	if (EBADMSG != pcp_msg_decode(&msg, mb)) goto error;

	if (msg)
		goto error;

	err = 0;

 error:
	mem_deref(mb);

	return err;
}


struct pcp_test {
	struct pcp_msg *msg;
	size_t respc;

	int err;
};


static void pcp_resp_handler(int err, struct pcp_msg *msg, void *arg)
{
	struct pcp_test *t = arg;

	if (err)
		goto out;

	TEST_EQUALS(true, msg->hdr.resp);
	TEST_EQUALS(PCP_MAP, msg->hdr.opcode);

	t->msg = mem_ref(msg);
	t->respc++;

 out:
	if (err) {
		if (err == ETIMEDOUT)
			err = ENOMEM;
		t->err = err;
	}

	/* done */
	re_cancel();
}


static int test_pcp_client_server(uint32_t lifetime,
				  enum pcp_result exp_result)
{
	static const struct pcp_conf pcp_conf = {3, 0, 1024, 1};
	struct pcpserver *srv = NULL;
	struct pcp_request *req = NULL;
	struct pcp_map map;
	struct pcp_test t;
	int err = 0;

	memset(&t, 0, sizeof(t));

	err = pcpserver_alloc(&srv, exp_result);
	if (err)
		goto out;

	map.proto    = IPPROTO_UDP;
	map.int_port = 2000;
	rand_bytes(map.nonce, sizeof(map.nonce));
	(void)sa_set_str(&map.ext_addr, "40.41.40.2", 4000);

	err = pcp_request(&req, &pcp_conf, &srv->addr, PCP_MAP, lifetime,
			  &map, pcp_resp_handler, &t, 0);
	if (err)
		goto out;

	err = re_main_timeout(1000);
	if (err || t.err)
		goto out;

	/* verify */
	TEST_ASSERT(srv->n_req >= 1);
	TEST_EQUALS(1, t.respc);
	TEST_EQUALS(lifetime, t.msg->hdr.lifetime);
	TEST_EQUALS(exp_result, t.msg->hdr.result);
	TEST_EQUALS(42, t.msg->hdr.epoch);
	TEST_MEMCMP(map.nonce, sizeof(map.nonce),
		    t.msg->pld.map.nonce, sizeof(t.msg->pld.map.nonce));
	TEST_EQUALS(map.proto, t.msg->pld.map.proto);
	TEST_EQUALS(map.int_port, t.msg->pld.map.int_port);
	TEST_SACMP(&map.ext_addr, &t.msg->pld.map.ext_addr, SA_ALL);

 out:
	mem_deref(req);
	mem_deref(srv);
	mem_deref(t.msg);

	return err ? err : t.err;
}


static int test_pcp_option(void)
{
	struct mbuf *mb;
	struct pcp_option *opt = NULL;
	struct sa addr;
	static const uint8_t opt_pkt[] = {
		0x01, 0x00, 0x00, 0x10,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff,
		0x0a, 0x00, 0x00, 0x01
	};
	int err;

	mb = mbuf_alloc(64);
	if (!mb)
		return ENOMEM;

	err = sa_set_str(&addr, "10.0.0.1", 0);
	if (err)
		goto out;

	err = pcp_option_encode(mb, PCP_OPTION_THIRD_PARTY, &addr);
	if (err)
		goto out;

	TEST_MEMCMP(opt_pkt, sizeof(opt_pkt), mb->buf, mb->end);

	mb->pos = 0;
	err = pcp_option_decode(&opt, mb);
	if (err)
		goto out;

	TEST_EQUALS(PCP_OPTION_THIRD_PARTY, opt->code);
	TEST_SACMP(&addr, &opt->u.third_party, SA_ADDR);

 out:
	mem_deref(opt);
	mem_deref(mb);
	return err;
}


int test_pcp(void)
{
	int err;

	err  = test_pcp_request_loop(0);
	err |= test_pcp_request_loop(4);
	if (err)
		return err;

	err = test_pcp_message();
	if (err)
		return err;

	err = test_pcp_option();
	if (err)
		return err;

	err = test_pcp_bad();
	if (err)
		return err;

	err  = test_pcp_client_server(60, PCP_SUCCESS);
	err |= test_pcp_client_server(0, PCP_SUCCESS);
	err |= test_pcp_client_server(60, PCP_NOT_AUTHORIZED);
	if (err)
		return err;

	return err;
}
