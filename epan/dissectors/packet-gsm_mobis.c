/* packet-gsm_mobis.c
 * Routines for packet dissection of Motorola GSM Mo-bis
 *
 * Copyright 2011 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id$
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/lapd_sapi.h>
#include <epan/prefs.h>

#include <stdio.h>

static int proto_gsm_mobis = -1;

static int ett_mobis = -1;
static int ett_ie = -1;

static int hf_exec_bit = -1;
static int hf_prio_bit = -1;
static int hf_hdr_ind = -1;
static int hf_comp_rout_ft = -1;
static int hf_length = -1;
static int hf_dest_mbox = -1;
static int hf_inst_loc_cell = -1;
static int hf_inst_link = -1;
static int hf_if_type = -1;
static int hf_msg_type_hdr = -1;
static int hf_msg_type = -1;

static int hf_iei = -1;
static int hf_sccprn_loc_cell_id = -1;
static int hf_sccprn_emerg_bit = -1;
static int hf_sccprn_sls = -1;
static int hf_sccprn_link = -1;
static int hf_sccprn_unique = -1;
static int hf_lci_loc_cell_id = -1;
static int hf_loc_carrier_id = -1;
static int hf_chan_req_cause = -1;
static int hf_ta_ta = -1;
static int hf_dlci_sapi = -1;
static int hf_cht_spd_ind = -1;
static int hf_cht_rate_type = -1;

static dissector_handle_t gsm_a_ccch_handle;
static dissector_handle_t gsm_a_dtap_handle;

typedef int dissect_fn(tvbuff_t *, int, packet_info *, proto_tree *);

struct value_dissect {
	guint32 val;
	dissect_fn *fn;
};

static const value_string comp_rf_vals[] = {
	{ 2,	"COMPACT_CRM" },
	{ 3,	"COMPACT_RRSSM" },
	{ 4,	"COMPACT_SSM" },
	{ 0,	NULL }
};
static const value_string msg_type_vals[] = {
	{ 0,	"L3INFO (Initial L3 Information)" },
	{ 1,	"RCHNREL (Radio Channel Released)" },
	{ 2,	"CIPHSUCC (Ciphering Success)" },
	{ 3,	"ASGNQUE (Assignment Queued)" },
	{ 4,	"RELREQ (Release Request)" },
	{ 5,	"UNSUCCASSGN (Unsuccessful Assignment)" },
	{ 6,	"ASGNSUCC (Assignment Success)" },
	{ 7,	"HOALLOC (Handover Allocation)" },
	{ 8,	"HOSUCC (Handover Success)" },
	{ 9,	"UNSUCCHO (Unsuccessful Handover)" },
	{ 10,	"INTHOINI (Internal Handover Initiated)" },
	{ 11,	"CIPHREQ (Ciphering Request)" },
	{ 12,	"INIASGN (Initial Assignment)" },
	{ 13,	"RELRCHN (Release Radio Channel)" },
	{ 14,	"INIHO (Initiate Handover)" },
	{ 15,	"BLCMD (Blast Command)" },
	{ 16,	"DEALOCSCCP (Deallocate SCCP Reference Number)" },
	{ 17,	"INTHOREQ (Internal Handover Request)" },
	{ 18,	"HORESNAVL (Handover Resources Not Available)" },
	{ 19,	"HODETREC (Handover Detect Received)" },
	{ 20,	"INFOREQ (Information Request)" },
	{ 24,	"SCCPASGN (SCCP Number Assigned)" },
	{ 25,	"DTAPMSG (DTAP Message)" },
	{ 26,	"UPDCLASS (Update Classmark)" },
	{ 31,	"REMQUE (Remove From Queue)" },
	{ 39,	"PAMOREQ (Page Mobile Request)" },
	{ 44,	"HORECREC (Handover Recognize Received)" },
	{ 45,	"INIICHO (Initiate Intra-Cell Handover)" },
	{ 72,	"HOFAIL (Handover Failure)" },
	{ 76,	"HLTBSS (Halt BSS)" },
	{ 77,	"HLTBSSACK (Halt BSS Ack)" },
	{ 78,	"STBSS (Start BSS)" },
	{ 78,	"STBSSACK (Start BSS Ack)" },
	{ 92,	"HOREQQUE (Handover Request Queued)" },
	{ 93,	"HOCANDENQ (Handover Candidate Enquiry)" },
	{ 94,	"HOCANDRESP (Handover Candidate Response Received)" },
	{ 97,	"REJSAPI3 (Reject SAPI 3)" },
	{ 98,	"SMSDTAPMSG (SMS DTAP Message)" },
	{ 99,	"CLLTRCRESP (Call Trace Response)" },
	{ 101,	"AUDCALL (Audit Call)" },
	{ 102,	"AUDSMCRSP (Audit SM Call Response)" },
	{ 104,	"AUDRSMCRSP (Audit RRSM Call Response)" },
	{ 128,	"GLRESET (Global Reset)" },
	{ 129,	"GLRESACK (Global Reset Ack)" },
	{ 0,	NULL }
};

static const value_string iei_vals[] = {
	{ 0x01, "GSM 08.71 Timing Advance" },
	{ 0x03, "Stats Cause" },
	{ 0x04, "Cause" },
	{ 0x07, "Internal Classmark" },
	{ 0x17, "Layer 3 Information" },
	{ 0x0B, "Channel Type" },
	{ 0x0D, "Interference Band" },
	{ 0x20, "Classmark Information type 3" },
	{ 0x30, "DLCI" },
	{ 0x3D, "GSM 04.08 Channel Request" },
	{ 0x64,	"Channel Description" },
	{ 0xF0,	"Local Cell Identifier" },
	{ 0xF1, "Local Carrier Identifier" },
	{ 0xF3,	"SCCP Reference Number" },
	{ 0, NULL }
};

static const value_string rrsm_iei_vals[] = {
	{ 0x0B, "Channel Type" },
	{ 0x18, "DLCI" },
	{ 0xF3,	"SCCP Reference Number" },
	{ 0, NULL }
};

static const value_string cht_spd_ind_vals[] = {
	{ 0x03, "Signalling" },
	/* FIXME */
	{ 0, NULL }
};

static const value_string cht_rate_type_vals[] = {
	{ 0x01, "SDCCH" },
	/* FIXME */
	{ 0, NULL }
};

struct ie_def {
	const value_string *val_str;
	const struct value_dissect *val_diss;
};

static int
dissect_sccp_ref_nr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	if (tree) {
		proto_tree_add_item(tree, hf_sccprn_loc_cell_id,
				    tvb, offset, 1, FALSE);
		proto_tree_add_item(tree, hf_sccprn_emerg_bit,
				    tvb, offset+1, 1, FALSE);
		proto_tree_add_item(tree, hf_sccprn_sls,
				    tvb, offset+1, 1, FALSE);
		proto_tree_add_item(tree, hf_sccprn_link,
				    tvb, offset+2, 1, FALSE);
		proto_tree_add_item(tree, hf_sccprn_unique,
				    tvb, offset+2, 1, FALSE);
	}
	return 3;
}

static int
dissect_local_cell_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_lci_loc_cell_id,
			    tvb, offset, 1, FALSE);
	return 1;
}

static int
dissect_local_carr_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_loc_carrier_id,
				    tvb, offset, 1, FALSE);
	return 1;
}

static int
dissect_chan_desc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	/* FIXME: hopping, ... */
	return 3;
}

static int
dissect_chan_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint8 length = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(tree, hf_cht_spd_ind,
			    tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_cht_rate_type,
			    tvb, offset, 1, FALSE);

	return 1 + length;
}

static int
dissect_dlci(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_dlci_sapi, tvb, offset, 1, FALSE);

	return 1;
}


static int
dissect_intf_band(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	return 1;
}

static int
dissect_chan_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_chan_req_cause,
			    tvb, offset, 1, FALSE);
	return 1;
}

static int
dissect_ta(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_ta_ta,
			    tvb, offset, 1, FALSE);
	return 1;
}

static int
dissect_int_classmark(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint8 length = tvb_get_guint8(tvb, offset);

	/* ignore user-supplied length, it sometime is wrong (1) */
	return 1 + 5;
}

static int
dissect_l3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint8 length = tvb_get_guint8(tvb, offset++);
	tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, length, length);

	/* FIXME: top_tree */
	call_dissector(gsm_a_dtap_handle, next_tvb, pinfo, tree);

	return 1 + length;
}

static int
dissect_rrsm_l3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint8 length;
	tvbuff_t *next_tvb;

	/* first octet is spare ?!? */
	offset++;
	length = tvb_get_guint8(tvb, offset++);
	next_tvb = tvb_new_subset(tvb, offset, length, length);

	/* FIXME: top_tree */
	call_dissector(gsm_a_dtap_handle, next_tvb, pinfo, tree);

	return 2 + length;
}

static int
dissect_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint8 length;

	length = tvb_get_guint8(tvb, offset++);

	/* Cause Value / Extension bit */

	return 1 + length;
}

static int
dissect_stats_cause(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree)
{
	/* FIXME */
	return 1;
}


static dissect_fn *
get_value_dissect(guint32 val, const struct value_dissect *vds)
{
	const struct value_dissect *vd;

	for (vd = vds; vd->val != 0 || vd->fn != NULL; vd++) {
		if (vd->val == val)
			return vd->fn;
	}
	return NULL;
}

static const struct value_dissect iei_diss[] = {
	{ 0x01, &dissect_ta },
	{ 0x03, &dissect_stats_cause },
	{ 0x04, &dissect_cause },
	{ 0x07, &dissect_int_classmark },
	{ 0x17, &dissect_l3 },
	{ 0x0B, &dissect_chan_type },
	{ 0x0D, &dissect_intf_band },
	//{ 0x20, "Classmark Information type 3" },
	{ 0x18, &dissect_dlci },
	{ 0x3D, &dissect_chan_req },
	{ 0x64,	&dissect_chan_desc },
	{ 0xF0,	&dissect_local_cell_id },
	{ 0xF1, &dissect_local_carr_id },
	{ 0xF3,	&dissect_sccp_ref_nr },
	{ 0, NULL }
};

static const struct value_dissect rrsm_iei_diss[] = {
	{ 0x0B, &dissect_rrsm_l3 },
	{ 0x18, &dissect_dlci },
	{ 0xF3,	&dissect_sccp_ref_nr },
	{ 0, NULL },
};


static const struct ie_def ie_defs[0xF] = {
	[2] = { iei_vals, iei_diss },
	[3] = { rrsm_iei_vals, rrsm_iei_diss },
	[4] = { iei_vals, iei_diss },
};


static int
dissect_ies(tvbuff_t *tvb, int offset, int length,
	    guint8 iei_type, packet_info *pinfo, proto_tree *tree)
{

	int cur = offset;
	static dissect_fn *fn;

	while (cur < offset + length) {
		guint8 iei = tvb_get_guint8(tvb, cur);
		const struct value_dissect *diss;
		proto_item *ti;
		proto_tree *ie_tree;

		ti = proto_tree_add_item(tree, hf_iei, tvb, cur++, 1, FALSE);
		ie_tree = proto_item_add_subtree(ti, ett_ie);

	        diss = ie_defs[iei_type].val_diss;
		if (!diss)
			break;

		fn = get_value_dissect(iei, diss);
		if (!fn) {
			printf("no diss. for IEI %u\n", iei);
			break;
		}
		cur += fn(tvb, cur, pinfo, ie_tree);
	}

	/* return total number of bytes consumed by this function */
	return cur - offset;
}


static void
dissect_gsm_mobis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *mobis_tree = NULL;
	proto_item *ti;
	guint tvb_len = tvb_length(tvb);

	guint8 length, msg_type, rout_type;
	int rc = -1;
	int offset = 0;
	int cur;

	length = tvb_get_guint8(tvb, offset+1);
	msg_type = tvb_get_guint8(tvb, offset+7);
	rout_type = tvb_get_guint8(tvb, offset) & 0xF;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_gsm_mobis, tvb, 0,
					 8+length, FALSE);
		mobis_tree = proto_item_add_subtree(ti, ett_mobis);

		/* first octet of executive header */
		proto_tree_add_item(mobis_tree, hf_exec_bit, tvb, offset, 1, TRUE);
		proto_tree_add_item(mobis_tree, hf_prio_bit, tvb, offset, 1, TRUE);
		proto_tree_add_item(mobis_tree, hf_hdr_ind, tvb, offset, 1, TRUE);
		proto_tree_add_item(mobis_tree, hf_comp_rout_ft, tvb, offset, 1, TRUE);

		/* remaining 7 octets of executive header */
		proto_tree_add_item(mobis_tree, hf_length, tvb, offset+1, 1, TRUE);
		proto_tree_add_item(mobis_tree, hf_dest_mbox, tvb,
				    offset+2, 2, FALSE);
		proto_tree_add_item(mobis_tree, hf_inst_loc_cell, tvb,
				    offset+4, 1, TRUE);
		proto_tree_add_item(mobis_tree, hf_inst_link, tvb,
				    offset+5, 1, TRUE);
		proto_tree_add_item(mobis_tree, hf_if_type, tvb,
				    offset+6, 1, TRUE);
		proto_tree_add_item(mobis_tree, hf_msg_type_hdr, tvb,
				    offset+7, 1, TRUE);
	}
	offset += 8;

	if (mobis_tree) {
		/* first octet of executive payload */
		proto_tree_add_item(mobis_tree, hf_msg_type, tvb,
				    offset++, 1, TRUE);
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, " %s ",
			val_to_str(msg_type, msg_type_vals, "%02d"));

	dissect_ies(tvb, offset, length-1, rout_type, pinfo, mobis_tree);
}

void
proto_reg_handoff_gsm_mobis(void);

void
proto_register_gsm_mobis(void)
{
	static hf_register_info hf[] = {
		{ &hf_exec_bit,
			{ "Executive Bit", "mobis.exec_bit",
			  FT_BOOLEAN, 8, NULL, 0x80,
			  NULL, HFILL }
		},
		{ &hf_prio_bit,
			{ "Priority Bit", "mobis.prio_bit",
			  FT_BOOLEAN, 8, NULL, 0x40,
			  NULL, HFILL }
		},
		{ &hf_hdr_ind,
			{ "Header Indicator", "mobis.hdr_ind",
			  FT_BOOLEAN, 8, NULL, 0x10,
			  NULL, HFILL }
		},
		{ &hf_comp_rout_ft,
			{ "Compact Routing Function Type", "mobis.compact.rft",
			  FT_UINT8, BASE_DEC, VALS(comp_rf_vals), 0x0F,
			  NULL, HFILL }
		},
		{ &hf_length,
			{ "Payload Length", "mobis.length",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_dest_mbox,
			{ "Destination Mailbox", "mobis.dest_mbox",
			  FT_UINT16, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_inst_loc_cell,
			{ "Instance (Local Cell)", "mobis.inst.loc_cell",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_inst_link,
			{ "Instance (BTS-BSC Link)", "mobis.inst.link",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_if_type,
			{ "Interface Type", "mobis.if_type",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_msg_type_hdr,
			{ "Message Type (Header)", "mobis.msg_type_hdr",
			  FT_UINT8, BASE_DEC, VALS(msg_type_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_msg_type,
			{ "Message Type", "mobis.msg_type",
			  FT_UINT8, BASE_DEC, VALS(msg_type_vals), 0,
			  NULL, HFILL }
		},

		{ &hf_iei,
			{ "IEI", "mobis.msg_type",
			  FT_UINT8, BASE_DEC, VALS(iei_vals), 0,
			  "Information Element Identifier", HFILL }
		},
		{ &hf_sccprn_loc_cell_id,
			{ "Local Cell ID", "mobis.sccp_rn.loc_cell_id",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_sccprn_emerg_bit,
			{ "Emergency bit", "mobis.sccp_rn.emerg_bit",
			  FT_BOOLEAN, 8, NULL, 0x80,
			  NULL, HFILL }
		},
		{ &hf_sccprn_sls,
			{ "SLS", "mobis.sccp_rn.sls",
			  FT_UINT8, BASE_DEC, NULL, 0x38,
			  NULL, HFILL }
		},
		{ &hf_sccprn_link,
			{ "BSC-BTS Link", "mobis.sccp_rn.link",
			  FT_UINT8, BASE_DEC, NULL, 0xe0,
			  NULL, HFILL }
		},
		{ &hf_sccprn_unique,
			{ "Unique bits", "mobis.sccp_rn.unique",
			  FT_UINT8, BASE_DEC, NULL, 0x1f,
			  NULL, HFILL }
		},
		{ &hf_lci_loc_cell_id,
			{ "Local Cell Id", "mobis.lci.loc_cell_id",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_loc_carrier_id,
			{ "Local Carrier Id", "mobis.loc_carr_id",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_chan_req_cause,
			{ "Channel Request Cause", "mobis.cr.chan_req_cause",
			  FT_UINT8, BASE_HEX, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_ta_ta,
			{ "Timing Advance", "mobis.ta.ta",
			  FT_UINT8, BASE_DEC, NULL, 0,
			  NULL, HFILL }
		},
		{ &hf_dlci_sapi,
			{ "SAPI", "mobis.dlci.sapi",
			  FT_UINT8, BASE_DEC, NULL, 0x07,
			  NULL, HFILL }
		},
		{ &hf_cht_spd_ind,
			{ "Speech/Data Indicator", "mobis.cht.spd_ind",
			  FT_UINT8, BASE_HEX, VALS(cht_spd_ind_vals), 0,
			  NULL, HFILL }
		},
		{ &hf_cht_rate_type,
			{ "Channel Rate/Type", "mobis.cht.rate_type",
			  FT_UINT8, BASE_HEX, VALS(cht_rate_type_vals), 0,
			  NULL, HFILL }
		},

	};
	static gint *ett[] = {
		&ett_mobis,
		&ett_ie,
	};

	module_t *mobis_module;

	proto_gsm_mobis = proto_register_protocol("Motorola GSM Mo-bis", "GSM Mo-bis",
						 "gsm_mobis");

	proto_register_field_array(proto_gsm_mobis, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gsm_mobis", dissect_gsm_mobis, proto_gsm_mobis);
}

/* This function is called once at startup and every time the user hits
 * 'apply' in the preferences dialogue */
void
proto_reg_handoff_gsm_mobis(void)
{
	static gboolean initialized = FALSE;

	if (!initialized) {
		dissector_handle_t gsm_mobis_handle;

		gsm_mobis_handle = create_dissector_handle(dissect_gsm_mobis, proto_gsm_mobis);
    		dissector_add_uint("lapd.gsm.sapi", 0, gsm_mobis_handle);

		gsm_a_ccch_handle = find_dissector("gsm_a_ccch");
		gsm_a_dtap_handle = find_dissector("gsm_a_dtap");
	} else {
		/* preferences have been changed */
	}
}
