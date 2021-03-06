/* packet-lucent_hnb.c
 * Routines for packet dissection of Alcatel/Lucent HomeNodeB
 * Copyright 2009 by Harald Welte <laforge@gnumonks.org>
 *
 * This protocol decoder is based entirely on reverse engineering, i.e.
 * on educated guesses.
 *
 * $Id: packet-lucent_hnb.c 29254 2009-07-31 19:19:25Z gerald $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define LHNB_SCTP_PPI_MM	1
#define LHNB_SCTP_PPI_GMM	6

#define LHNB_SCTP_PORT		6005

#include <glib.h>

#include <epan/packet.h>

/* Initialize the protocol and registered fields */
static int proto_lhnb = -1;

static int hf_lhnb_length = -1;

/* Initialize the subtree pointers */
static gint ett_lhnb = -1;

static dissector_handle_t ranap_handle;

/* Code to actually dissect the packets */
static void
dissect_lhnb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	int offset = 0;
	u_int16_t len;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LHNB");
	col_clear(pinfo->cinfo, COL_INFO);

	proto_tree_add_item(tree, hf_lhnb_length, tvb, offset+2, 2, FALSE);
	len = tvb_get_ntohs(tvb, offset+2);
	next_tvb = tvb_new_subset(tvb, offset+2+6, len-4, -1);

	call_dissector(ranap_handle, next_tvb, pinfo, tree);
}

void proto_register_lucent_hnb(void)
{
	static hf_register_info hf[] = {
		{&hf_lhnb_length,
		 {"Length", "lhnb.len",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		 },
	};

	static gint *ett[] = {
		&ett_lhnb,
	};

	proto_lhnb =
	    proto_register_protocol("Alcatel/Lucent HomeNodeB",
				    "Lucent HNB", "lhnb");

	proto_register_field_array(proto_lhnb, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_lucent_hnb(void)
{
	dissector_handle_t lhnb_handle;

	ranap_handle = find_dissector("ranap");

	lhnb_handle = create_dissector_handle(dissect_lhnb, proto_lhnb);

	dissector_add("sctp.ppi", LHNB_SCTP_PPI_MM, lhnb_handle);
	dissector_add("sctp.ppi", LHNB_SCTP_PPI_GMM, lhnb_handle);
	dissector_add("sctp.port", LHNB_SCTP_PORT, lhnb_handle);
}
