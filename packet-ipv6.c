/* packet-ipv6.c
 * Routines for IPv6 packet disassembly 
 *
 * $Id: packet-ipv6.c,v 1.45 2000/11/17 06:02:20 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_h
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <stdio.h>
#include <glib.h>
#include "etypes.h"
#include "ppptypes.h"
#include "aftypes.h"
#include "packet.h"
#include "packet-ip.h"
#include "packet-ipsec.h"
#include "packet-ipv6.h"
#include "packet-tcp.h"
#include "packet-udp.h"
#include "resolv.h"

/*
 * NOTE: ipv6.nxt is not very useful as we will have chained header.
 * now testing ipv6.final, but it raises SEGV.
#define TEST_FINALHDR
 */

static int proto_ipv6 = -1;
static int hf_ipv6_version = -1;
static int hf_ipv6_class = -1;
static int hf_ipv6_flow = -1;
static int hf_ipv6_plen = -1;
static int hf_ipv6_nxt = -1;
static int hf_ipv6_hlim = -1;
static int hf_ipv6_src = -1;
static int hf_ipv6_dst = -1;
static int hf_ipv6_addr = -1;
#ifdef TEST_FINALHDR
static int hf_ipv6_final = -1;
#endif

static gint ett_ipv6 = -1;

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif

static int
dissect_routing6(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    struct ip6_rthdr rt;
    int len;
    proto_tree *rthdr_tree;
	proto_item *ti;
    char buf[sizeof(struct ip6_rthdr0) + sizeof(struct e_in6_addr) * 23];

    memcpy(&rt, (void *) &pd[offset], sizeof(rt));
    len = (rt.ip6r_len + 1) << 3;

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_text(tree, NullTVB, offset, len,
	    "Routing Header, Type %u", rt.ip6r_type);
	rthdr_tree = proto_item_add_subtree(ti, ett_ipv6);

	proto_tree_add_text(rthdr_tree, NullTVB,
	    offset + offsetof(struct ip6_rthdr, ip6r_nxt), 1,
	    "Next header: %s (0x%02x)", ipprotostr(rt.ip6r_nxt), rt.ip6r_nxt);
	proto_tree_add_text(rthdr_tree, NullTVB,
	    offset + offsetof(struct ip6_rthdr, ip6r_len), 1,
	    "Length: %u (%d bytes)", rt.ip6r_len, len);
	proto_tree_add_text(rthdr_tree, NullTVB,
	    offset + offsetof(struct ip6_rthdr, ip6r_type), 1,
	    "Type: %u", rt.ip6r_type);
	proto_tree_add_text(rthdr_tree, NullTVB,
	    offset + offsetof(struct ip6_rthdr, ip6r_segleft), 1,
	    "Segments left: %u", rt.ip6r_segleft);

	if (rt.ip6r_type == 0 && len <= sizeof(buf)) {
	    struct e_in6_addr *a;
	    int n;
	    struct ip6_rthdr0 *rt0;

	    memcpy(buf, (void *) &pd[offset], len);
	    rt0 = (struct ip6_rthdr0 *)buf;
	    for (a = rt0->ip6r0_addr, n = 0;
		 a < (struct e_in6_addr *)(buf + len);
		 a++, n++) {
		proto_tree_add_text(rthdr_tree, NullTVB,
		    offset + offsetof(struct ip6_rthdr0, ip6r0_addr) + n * sizeof(struct e_in6_addr),
		    sizeof(struct e_in6_addr),
#ifdef INET6
		    "address %d: %s (%s)",
		    n, get_hostname6(a), ip6_to_str(a)
#else
		    "address %d: %s", n, ip6_to_str(a)
#endif
		    );
	    }
	}
  
	/* decode... */
    }

    return len;
}

static int
dissect_frag6(const u_char *pd, int offset, frame_data *fd, proto_tree *tree, 
    int *fragstart) {
    struct ip6_frag frag;
    int len;
    proto_item *ti;
    proto_tree *rthdr_tree;

    memcpy(&frag, (void *) &pd[offset], sizeof(frag));
    len = sizeof(frag);
    frag.ip6f_offlg = ntohs(frag.ip6f_offlg);
    *fragstart = frag.ip6f_offlg & IP6F_OFF_MASK;
    if (check_col(fd, COL_INFO)) {
	col_add_fstr(fd, COL_INFO,
	    "IPv6 fragment (nxt=%s (0x%02x) off=%u id=0x%x)",
	    ipprotostr(frag.ip6f_nxt), frag.ip6f_nxt,
	    *fragstart, frag.ip6f_ident);
    }
    if (tree) {
	   ti = proto_tree_add_text(tree, NullTVB, offset, len,
			   "Fragmention Header");
	   rthdr_tree = proto_item_add_subtree(ti, ett_ipv6);

	   proto_tree_add_text(rthdr_tree, NullTVB,
			 offset + offsetof(struct ip6_frag, ip6f_nxt), 1,
			 "Next header: %s (0x%02x)",
			 ipprotostr(frag.ip6f_nxt), frag.ip6f_nxt);

	#if 0
	   proto_tree_add_text(rthdr_tree, NullTVB,
			 offset + offsetof(struct ip6_frag, ip6f_reserved), 1,
			 "Reserved: %u",
			 frag.ip6f_reserved);
	#endif

	   proto_tree_add_text(rthdr_tree, NullTVB,
			 offset + offsetof(struct ip6_frag, ip6f_offlg), 2,
			 "Offset: %u",
			 frag.ip6f_offlg & IP6F_OFF_MASK);

	   proto_tree_add_text(rthdr_tree, NullTVB,
			 offset + offsetof(struct ip6_frag, ip6f_offlg), 2,
			 "More fragments: %s",
				frag.ip6f_offlg & IP6F_MORE_FRAG ?
				"Yes" : "No");

	   proto_tree_add_text(rthdr_tree, NullTVB,
			 offset + offsetof(struct ip6_frag, ip6f_ident), 4,
			 "Identification: 0x%08x",
			 frag.ip6f_ident);
    }
    return len;
}

static int
dissect_opts(const u_char *pd, int offset, frame_data *fd, proto_tree *tree,
    char *optname) {
    struct ip6_ext ext;
    int len;
    proto_tree *dstopt_tree;
	proto_item *ti;
    u_char *p;
    static const value_string rtalertvals[] = {
	{ IP6OPT_RTALERT_MLD, "MLD" },
	{ IP6OPT_RTALERT_RSVP, "RSVP" },
	{ 0, NULL },
    };

    memcpy(&ext, (void *) &pd[offset], sizeof(ext)); 
    len = (ext.ip6e_len + 1) << 3;

    if (tree) {
	/* !!! specify length */
	ti = proto_tree_add_text(tree, NullTVB, offset, len,
	    "%s Header", optname);
	dstopt_tree = proto_item_add_subtree(ti, ett_ipv6);

	proto_tree_add_text(dstopt_tree, NullTVB,
	    offset + offsetof(struct ip6_ext, ip6e_nxt), 1,
	    "Next header: %s (0x%02x)", ipprotostr(ext.ip6e_nxt), ext.ip6e_nxt);
	proto_tree_add_text(dstopt_tree, NullTVB,
	    offset + offsetof(struct ip6_ext, ip6e_len), 1,
	    "Length: %u (%d bytes)", ext.ip6e_len, len);

	p = (u_char *)(pd + offset + 2);
	while (p < pd + offset + len) {
	    switch (p[0]) {
	    case IP6OPT_PAD1:
		proto_tree_add_text(dstopt_tree, NullTVB, p - pd, 1,
		    "Pad1");
		p++;
		break;
	    case IP6OPT_PADN:
		proto_tree_add_text(dstopt_tree, NullTVB, p - pd, p[1] + 2,
		    "PadN: %u bytes", p[1] + 2);
		p += p[1];
		p += 2;
		break;
	    case IP6OPT_JUMBO:
		if (p[1] == 4) {
		    proto_tree_add_text(dstopt_tree, NullTVB, p - pd, p[1] + 2,
			"Jumbo payload: %u (%u bytes)",
			pntohl(&p[2]), p[1] + 2);
		} else {
		    proto_tree_add_text(dstopt_tree, NullTVB, p - pd, p[1] + 2,
			"Jumbo payload: Invalid length (%u bytes)",
			p[1] + 2);
		}
		p += p[1];
		p += 2;
		break;
	    case IP6OPT_RTALERT:
	      {
		char *rta;

		if (p[1] == 2) {
		    rta = val_to_str(pntohs(&p[2]), rtalertvals,
				"Unknown");
		} else
		    rta = "Invalid length";
		ti = proto_tree_add_text(dstopt_tree, NullTVB, p - pd, p[1] + 2,
		    "Router alert: %s (%u bytes)", rta, p[1] + 2);
		p += p[1];
		p += 2;
		break;
	      }
	    default:
		p = (u_char *)(pd + offset + len);
		break;
	    }
	}

	/* decode... */
    }

    return len;
}

static int
dissect_hopopts(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    return dissect_opts(pd, offset, fd, tree, "Hop-by-hop Option");
}

static int
dissect_dstopts(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
    return dissect_opts(pd, offset, fd, tree, "Destination Option");
}

void
dissect_ipv6(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  proto_tree *ipv6_tree;
  proto_item *ti;
  guint8 nxt;
  int advance;
  int poffset;
  int frag;

  struct ip6_hdr ipv6;

  OLD_CHECK_DISPLAY_AS_DATA(proto_ipv6, pd, offset, fd, tree);

  memcpy(&ipv6, (void *) &pd[offset], sizeof(ipv6)); 

  pi.ipproto = ipv6.ip6_nxt; /* XXX make work TCP follow (ipproto = 6) */

  SET_ADDRESS(&pi.net_src, AT_IPv6, 16, &pd[offset + IP6H_SRC]);
  SET_ADDRESS(&pi.src, AT_IPv6, 16, &pd[offset + IP6H_SRC]);
  SET_ADDRESS(&pi.net_dst, AT_IPv6, 16, &pd[offset + IP6H_DST]);
  SET_ADDRESS(&pi.dst, AT_IPv6, 16, &pd[offset + IP6H_DST]);

  if (tree) {
    /* !!! specify length */
    ti = proto_tree_add_item(tree, proto_ipv6, NullTVB, offset, 40, FALSE);
    ipv6_tree = proto_item_add_subtree(ti, ett_ipv6);

    /* !!! warning: version also contains 4 Bit priority */
    proto_tree_add_uint(ipv6_tree, hf_ipv6_version, NullTVB,
		offset + offsetof(struct ip6_hdr, ip6_vfc), 1,
		(ipv6.ip6_vfc >> 4) & 0x0f);


    proto_tree_add_uint(ipv6_tree, hf_ipv6_class, NullTVB,
		offset + offsetof(struct ip6_hdr, ip6_flow), 4,
		(guint8)((ntohl(ipv6.ip6_flow) >> 20) & 0xff));

    /*
     * there should be no alignment problems for ip6_flow, since it's the first
     * guint32 in the ipv6 struct
     */
    proto_tree_add_uint_format(ipv6_tree, hf_ipv6_flow, NullTVB,
		offset + offsetof(struct ip6_hdr, ip6_flow), 4,
		(unsigned long)(ntohl(ipv6.ip6_flow) & IPV6_FLOWLABEL_MASK),
		"Flowlabel: 0x%05lx",
		(unsigned long)(ntohl(ipv6.ip6_flow) & IPV6_FLOWLABEL_MASK));

    proto_tree_add_uint(ipv6_tree, hf_ipv6_plen, NullTVB,
		offset + offsetof(struct ip6_hdr, ip6_plen), 2,
		ntohs(ipv6.ip6_plen));

    proto_tree_add_uint_format(ipv6_tree, hf_ipv6_nxt, NullTVB,
		offset + offsetof(struct ip6_hdr, ip6_nxt), 1,
		ipv6.ip6_nxt,
		"Next header: %s (0x%02x)",
		ipprotostr(ipv6.ip6_nxt), ipv6.ip6_nxt);

    proto_tree_add_uint(ipv6_tree, hf_ipv6_hlim, NullTVB,
		offset + offsetof(struct ip6_hdr, ip6_hlim), 1,
		ipv6.ip6_hlim);

    proto_tree_add_ipv6_hidden(ipv6_tree, hf_ipv6_addr, NullTVB, 
			       offset + offsetof(struct ip6_hdr, ip6_src), 16,
			       ipv6.ip6_src.s6_addr8);
    proto_tree_add_ipv6_hidden(ipv6_tree, hf_ipv6_addr, NullTVB, 
			       offset + offsetof(struct ip6_hdr, ip6_dst), 16,
			       ipv6.ip6_dst.s6_addr8);

    proto_tree_add_ipv6_format(ipv6_tree, hf_ipv6_src, NullTVB,
		offset + offsetof(struct ip6_hdr, ip6_src), 16,
		(guint8 *)&ipv6.ip6_src,
#ifdef INET6
		"Source address: %s (%s)",
		get_hostname6(&ipv6.ip6_src),
#else
		"Source address: %s",
#endif
		ip6_to_str(&ipv6.ip6_src));

    proto_tree_add_ipv6_format(ipv6_tree, hf_ipv6_dst, NullTVB,
		offset + offsetof(struct ip6_hdr, ip6_dst), 16,
		(guint8 *)&ipv6.ip6_dst,
#ifdef INET6
		"Destination address: %s (%s)",
		get_hostname6(&ipv6.ip6_dst),
#else
		"Destination address: %s",
#endif
		ip6_to_str(&ipv6.ip6_dst));
  }

  /* start of the new header (could be a extension header) */
  nxt = pd[poffset = offset + offsetof(struct ip6_hdr, ip6_nxt)];
  offset += sizeof(struct ip6_hdr);
  frag = 0;

again:
    switch (nxt) {
    case IP_PROTO_HOPOPTS:
	advance = dissect_hopopts(pd, offset, fd, tree);
	nxt = pd[poffset = offset];
	offset += advance;
	goto again;
    case IP_PROTO_ROUTING:
	advance = dissect_routing6(pd, offset, fd, tree);
	nxt = pd[poffset = offset];
	offset += advance;
	goto again;
    case IP_PROTO_FRAGMENT:
	advance = dissect_frag6(pd, offset, fd, tree, &frag);
	nxt = pd[poffset = offset];
	offset += advance;
	goto again;
    case IP_PROTO_AH:
	advance = dissect_ah_old(pd, offset, fd, tree);
	nxt = pd[poffset = offset];
	offset += advance;
	goto again;
    case IP_PROTO_DSTOPTS:
	advance = dissect_dstopts(pd, offset, fd, tree);
	nxt = pd[poffset = offset];
	offset += advance;
	goto again;
    }

#ifdef TEST_FINALHDR
  proto_tree_add_uint_hidden(ipv6_tree, hf_ipv6_final, NullTVB, poffset, 1, nxt);
#endif
  if (frag) {
    /* fragmented */
    if (check_col(fd, COL_PROTOCOL))
      col_add_str(fd, COL_PROTOCOL, "IPv6");
    /* COL_INFO was filled in by "dissect_frag6()" */
    old_dissect_data(pd, offset, fd, tree);
  } else {
    /* do lookup with the subdissector table */
    if (!old_dissector_try_port(ip_dissector_table, nxt, pd, offset, fd, tree)) {
      /* Unknown protocol */
      if (check_col(fd, COL_PROTOCOL))
	col_add_str(fd, COL_PROTOCOL, "IPv6");
      if (check_col(fd, COL_INFO))
	col_add_fstr(fd, COL_INFO, "%s (0x%02x)", ipprotostr(nxt), nxt);
      old_dissect_data(pd, offset, fd, tree);
    }
  }
}

static void
dissect_ipv6_none(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  if (check_col(fd, COL_INFO))
    col_add_fstr(fd, COL_INFO, "IPv6 no next header");

  /* XXX - dissect the payload as padding? */
}

void
proto_register_ipv6(void)
{
  static hf_register_info hf[] = {
    { &hf_ipv6_version,
      { "Version",		"ipv6.version",
				FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
    { &hf_ipv6_class,
      { "Traffic class",	"ipv6.class",
				FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
    { &hf_ipv6_flow,
      { "Flowlabel",		"ipv6.flow",
				FT_UINT32, BASE_HEX, NULL, 0x0, "" }},
    { &hf_ipv6_plen,
      { "Payload length",	"ipv6.plen",
				FT_UINT16, BASE_DEC, NULL, 0x0, "" }},
    { &hf_ipv6_nxt,
      { "Next header",		"ipv6.nxt",
				FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
    { &hf_ipv6_hlim,
      { "Hop limit",		"ipv6.hlim",
				FT_UINT8, BASE_DEC, NULL, 0x0, "" }},
    { &hf_ipv6_src,
      { "Source",		"ipv6.src",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Source IPv6 Address" }},
    { &hf_ipv6_dst,
      { "Destination",		"ipv6.dst",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Destination IPv6 Address" }},
    { &hf_ipv6_addr,
      { "Address",		"ipv6.addr",
				FT_IPv6, BASE_NONE, NULL, 0x0,
				"Source or Destination IPv6 Address" }},
#ifdef TEST_FINALHDR
    { &hf_ipv6_final,
      { "Final next header",	"ipv6.final",
				FT_UINT8, BASE_HEX, NULL, 0x0, "" }},
#endif
  };
  static gint *ett[] = {
    &ett_ipv6,
  };

  proto_ipv6 = proto_register_protocol("Internet Protocol Version 6", "ipv6");
  proto_register_field_array(proto_ipv6, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipv6(void)
{
	old_dissector_add("ethertype", ETHERTYPE_IPv6, dissect_ipv6);
	old_dissector_add("ppp.protocol", PPP_IPV6, dissect_ipv6);
	old_dissector_add("ip.proto", IP_PROTO_IPV6, dissect_ipv6);
	old_dissector_add("null.type", BSD_AF_INET6_BSD, dissect_ipv6);
	old_dissector_add("null.type", BSD_AF_INET6_FREEBSD, dissect_ipv6);
	old_dissector_add("ip.proto", IP_PROTO_NONE, dissect_ipv6_none);
}
