/**
 * @file mock/pcpsrv.c Mock PCP server
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re.h>
#include <rew.h>
#include "test.h"


#define DEBUG_MODULE "mock/pcpsrv"
#define DEBUG_LEVEL 5
#include <re_dbg.h>


static void udp_recv(const struct sa *src, struct mbuf *mb, void *arg)
{
	struct pcpserver *srv = arg;
	struct pcp_msg *msg = NULL;
	enum pcp_opcode opcode;
	size_t start = mb->pos;
	int err = 0;

	opcode = mbuf_buf(mb)[1];

	++srv->n_req;

	err = pcp_msg_decode(&msg, mb);
	if (err)
		goto out;

	/* verify PCP request */
	TEST_EQUALS(PCP_VERSION, msg->hdr.version);
	TEST_EQUALS(0, msg->hdr.resp);
	TEST_ASSERT(sa_isset(&msg->hdr.cli_addr, SA_ADDR));

	mb->pos = start;
	err = pcp_reply(srv->us, src, mb, opcode, srv->result,
			msg->hdr.lifetime, 42, &msg->pld);
	if (err)
		goto out;

 out:
	if (err) {
		DEBUG_WARNING("server error: %m\n", err);
	}

	mem_deref(msg);
}


static void pcpserver_destructor(void *arg)
{
	struct pcpserver *srv = arg;

	mem_deref(srv->us);
}


int pcpserver_alloc(struct pcpserver **srvp, int result)
{
	struct pcpserver *srv;
	int err;

	srv = mem_zalloc(sizeof(*srv), pcpserver_destructor);
	if (!srv)
		return ENOMEM;

	srv->result = result;

	err = sa_set_str(&srv->addr, "127.0.0.1", 0);
	if (err)
		goto out;

	err = udp_listen(&srv->us, &srv->addr, udp_recv, srv);
	if (err)
		goto out;

	err = udp_local_get(srv->us, &srv->addr);
	if (err)
		goto out;

 out:
	if (err)
		mem_deref(srv);
	else
		*srvp = srv;

	return err;
}
