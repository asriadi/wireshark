/* packet-rtp.c
 *
 * Routines for uRTP dissection
 * uRTP = micro Real time Transport Protocol
 *
 * Copyright 2011, Harald Welte <laforge@gnumonks.org>
 *
 * $Id: packet-urtp.c 35883 2011-02-09 02:27:41Z morriss $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>

#include "packet-rtp.h"
#include <epan/rtp_pt.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/tap.h>

#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/strutil.h>

static dissector_handle_t urtp_handle;

static int urtp_tap = -1;

/* uRTP header fields             */
static int proto_urtp           = -1;
static int hf_urtp_marker       = -1;
static int hf_urtp_payload_type = -1;
static int hf_urtp_timestamp    = -1;
static int hf_urtp_num_frames   = -1;
static int hf_urtp_ssrc         = -1;
static int hf_urtp_data         = -1;

/* uRTP fields defining a sub tree */
static gint ett_urtp       = -1;

/* Forward declaration we need below */
void proto_reg_handoff_urtp(void);

static dissector_handle_t data_handle;
static dissector_handle_t amr_handle;

static const value_string urtp_payload_type_vals[] =
{
	{ 0,		NULL },
};

value_string_ext urtp_payload_type_vals_ext = VALUE_STRING_EXT_INIT(urtp_payload_type_vals);


#if 0
/*
 * Process the payload of the RTP packet, hand it to the subdissector
 */
static void
process_rtp_payload(tvbuff_t *newtvb, packet_info *pinfo, proto_tree *tree,
		    proto_tree *rtp_tree,
		    unsigned int payload_type)
{
	struct _rtp_conversation_info *p_conv_data = NULL;
	gboolean found_match = FALSE;
	int payload_len;
	struct srtp_info *srtp_info;
	int offset=0;

	payload_len = tvb_length_remaining(newtvb, offset);

	/* first check if this is added as an SRTP stream - if so, don't try to dissector the payload data for now */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);
	if (p_conv_data && p_conv_data->srtp_info) {
		srtp_info = p_conv_data->srtp_info;
		payload_len -= srtp_info->mki_len + srtp_info->auth_tag_len;
#if 0
#error Currently the srtp_info structure contains no cypher data, see packet-sdp.c adding dummy_srtp_info structure
		if (p_conv_data->srtp_info->encryption_algorithm==SRTP_ENC_ALG_NULL) {
			if (rtp_tree)
				proto_tree_add_text(rtp_tree, newtvb, offset, payload_len, "SRTP Payload with NULL encryption");
		}
		else
#endif
		{
			if (rtp_tree)
				proto_tree_add_item(rtp_tree, hf_srtp_encrypted_payload, newtvb, offset, payload_len, FALSE);
			found_match = TRUE;	/* use this flag to prevent dissection below */
		}
		offset += payload_len;

		if (srtp_info->mki_len) {
			proto_tree_add_item(rtp_tree, hf_srtp_mki, newtvb, offset, srtp_info->mki_len, FALSE);
			offset += srtp_info->mki_len;
		}

		if (srtp_info->auth_tag_len) {
			proto_tree_add_item(rtp_tree, hf_srtp_auth_tag, newtvb, offset, srtp_info->auth_tag_len, FALSE);
			offset += srtp_info->auth_tag_len;
		}
	}

	/* if the payload type is dynamic, we check if the conv is set and we look for the pt definition */
	else if ( (payload_type >= PT_UNDF_96 && payload_type <= PT_UNDF_127) ) {
		if (p_conv_data && p_conv_data->rtp_dyn_payload) {
			gchar *payload_type_str = NULL;
			encoding_name_and_rate_t *encoding_name_and_rate_pt = NULL;
			encoding_name_and_rate_pt = g_hash_table_lookup(p_conv_data->rtp_dyn_payload, &payload_type);
			if (encoding_name_and_rate_pt) {
				payload_type_str = encoding_name_and_rate_pt->encoding_name;
			}
			if (payload_type_str){
				found_match = dissector_try_string(rtp_dyn_pt_dissector_table,
								   payload_type_str, newtvb, pinfo, tree);
				/* If payload type string set from conversation and
				 * no matching dissector found it's probably because no subdissector
				 * exists. Don't call the dissectors based on payload number
				 * as that'd probably be the wrong dissector in this case.
				 * Just add it as data.
				 */
				if(found_match==FALSE)
					proto_tree_add_item( rtp_tree, hf_rtp_data, newtvb, 0, -1, FALSE );
				return;
			}

		}
	}

	/* if we don't found, it is static OR could be set static from the preferences */
	if (!found_match && !dissector_try_uint(rtp_pt_dissector_table, payload_type, newtvb, pinfo, tree))
		proto_tree_add_item( rtp_tree, hf_rtp_data, newtvb, 0, -1, FALSE );

}

/* Rtp payload reassembly
 *
 * This handles the reassembly of PDUs for higher-level protocols.
 *
 * We're a bit limited on how we can cope with out-of-order packets, because
 * we don't have any idea of where the datagram boundaries are. So if we see
 * packets A, C, B (all of which comprise a single datagram), we cannot know
 * that C should be added to the same datagram as A, until we come to B (which
 * may or may not actually be present...).
 *
 * What we end up doing in this case is passing A+B to the subdissector as one
 * datagram, and make out that a new one starts on C.
 */
static void
dissect_rtp_data( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		  proto_tree *rtp_tree, int offset, unsigned int data_len,
		  unsigned int data_reported_len,
		  unsigned int payload_type )
{
	tvbuff_t *newtvb;
	struct _rtp_conversation_info *p_conv_data= NULL;
	gboolean must_desegment = FALSE;
	rtp_private_conv_info *finfo = NULL;
	rtp_multisegment_pdu *msp = NULL;
	guint32 seqno;

	/* Retrieve RTPs idea of a converation */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);

	if(p_conv_data != NULL)
		finfo = p_conv_data->rtp_conv_info;

	if(finfo == NULL || !desegment_rtp) {
		/* Hand the whole lot off to the subdissector */
		newtvb=tvb_new_subset(tvb,offset,data_len,data_reported_len);
		process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type);
		return;
	}

	seqno = p_conv_data->extended_seqno;

	pinfo->can_desegment = 2;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;

#ifdef DEBUG_FRAGMENTS
	g_debug("%d: RTP Part of convo %d(%p); seqno %d",
		pinfo->fd->num,
		p_conv_data->frame_number, p_conv_data,
		seqno
		);
#endif

	/* look for a pdu which we might be extending */
	msp = (rtp_multisegment_pdu *)se_tree_lookup32_le(finfo->multisegment_pdus,seqno-1);

	if(msp && msp->startseq < seqno && msp->endseq >= seqno) {
		guint32 fid = msp->startseq;
		fragment_data *fd_head;

#ifdef DEBUG_FRAGMENTS
		g_debug("\tContinues fragment %d", fid);
#endif

		/* we always assume the datagram is complete; if this is the
		 * first pass, that's our best guess, and if it's not, what we
		 * say gets ignored anyway.
		 */
		fd_head = fragment_add_seq(tvb, offset, pinfo, fid, fragment_table,
					   seqno-msp->startseq, data_len, FALSE);

		newtvb = process_reassembled_data(tvb,offset, pinfo, "Reassembled RTP", fd_head,
						  &rtp_fragment_items, NULL, tree);

#ifdef DEBUG_FRAGMENTS
		g_debug("\tFragment Coalesced; fd_head=%p, newtvb=%p (len %d)",fd_head, newtvb,
			newtvb?tvb_reported_length(newtvb):0);
#endif

		if(newtvb != NULL) {
			/* Hand off to the subdissector */
			process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type);

			/*
			 * Check to see if there were any complete fragments within the chunk
			 */
			if( pinfo->desegment_len && pinfo->desegment_offset == 0 )
			{
#ifdef DEBUG_FRAGMENTS
				g_debug("\tNo complete pdus in payload" );
#endif
				/* Mark the fragments and not complete yet */
				fragment_set_partial_reassembly(pinfo, fid, fragment_table);

				/* we must need another segment */
				msp->endseq = MIN(msp->endseq,seqno) + 1;
			}
			else
			{
				/*
				 * Data was dissected so add the protocol tree to the display
				 */
				proto_item *rtp_tree_item, *frag_tree_item;
				/* this nargery is to insert the fragment tree into the main tree
				 * between the RTP protocol entry and the subdissector entry */
				show_fragment_tree(fd_head, &rtp_fragment_items, tree, pinfo, newtvb, &frag_tree_item);
				rtp_tree_item = proto_item_get_parent( proto_tree_get_parent( rtp_tree ));
				if( frag_tree_item && rtp_tree_item )
					proto_tree_move_item( tree, rtp_tree_item, frag_tree_item );


				if(pinfo->desegment_len)
				{
					/* the higher-level dissector has asked for some more data - ie,
					   the end of this segment does not coincide with the end of a
					   higher-level PDU. */
					must_desegment = TRUE;
				}
			}

		}

	}
	else
	{
		/*
		 * The segment is not the continuation of a fragmented segment
		 * so process it as normal
		 */
#ifdef DEBUG_FRAGMENTS
		g_debug("\tRTP non-fragment payload");
#endif
		newtvb = tvb_new_subset( tvb, offset, data_len, data_reported_len );

		/* Hand off to the subdissector */
		process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type);

		if(pinfo->desegment_len) {
			/* the higher-level dissector has asked for some more data - ie,
			   the end of this segment does not coincide with the end of a
			   higher-level PDU. */
			must_desegment = TRUE;
		}
	}

	/*
	 * There were bytes left over that the higher protocol couldn't dissect so save them
	 */
	if(must_desegment)
	{
		guint32 deseg_offset = pinfo->desegment_offset;
		guint32 frag_len = tvb_reported_length_remaining(newtvb, deseg_offset);
		fragment_data *fd_head = NULL;

#ifdef DEBUG_FRAGMENTS
		g_debug("\tRTP Must Desegment: tvb_len=%d ds_len=%d %d frag_len=%d ds_off=%d",
			tvb_reported_length(newtvb),
			pinfo->desegment_len,
			pinfo->fd->flags.visited,
			frag_len,
			deseg_offset);
#endif
		/* allocate a new msp for this pdu */
		msp = se_alloc(sizeof(rtp_multisegment_pdu));
		msp->startseq = seqno;
		msp->endseq = seqno+1;
		se_tree_insert32(finfo->multisegment_pdus,seqno,msp);

		/*
		 * Add the fragment to the fragment table
		 */
		fd_head = fragment_add_seq(newtvb,deseg_offset, pinfo, seqno, fragment_table, 0, frag_len,
					   TRUE );

		if(fd_head != NULL)
		{
			if( fd_head->reassembled_in != 0 && !(fd_head->flags & FD_PARTIAL_REASSEMBLY) )
			{
				proto_item *rtp_tree_item;
				rtp_tree_item = proto_tree_add_uint( tree, hf_rtp_reassembled_in,
								     newtvb, deseg_offset, tvb_reported_length_remaining(newtvb,deseg_offset),
								     fd_head->reassembled_in);
				PROTO_ITEM_SET_GENERATED(rtp_tree_item);
#ifdef DEBUG_FRAGMENTS
				g_debug("\tReassembled in %d", fd_head->reassembled_in);
#endif
			}
			else
			{
#ifdef DEBUG_FRAGMENTS
				g_debug("\tUnfinished fragment");
#endif
				/* this fragment is never reassembled */
				proto_tree_add_text( tree, tvb, deseg_offset, -1,"RTP fragment, unfinished");
			}
		}
		else
		{
			/*
			 * This fragment was the first fragment in a new entry in the
			 * frag_table; we don't yet know where it is reassembled
			 */
#ifdef DEBUG_FRAGMENTS
			g_debug("\tnew pdu");
#endif
		}

		if( pinfo->desegment_offset == 0 )
		{
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP");
			col_set_str(pinfo->cinfo, COL_INFO, "[RTP segment of a reassembled PDU]");
		}
	}



	pinfo->can_desegment = 0;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;
}
#endif

static const unsigned int amr_ft_len_bits[] = {
	[0]	= 95,
	[1]	= 103,
	[2]	= 118,
	[3]	= 134,
	[4]	= 148,
	[5]	= 159,
	[6]	= 204,
	[7]	= 244,
	[8]	= 39,
};

static int amr_bytelen_padded(guint8 ft)
{
	unsigned int bits;
	int bytes;

	if (ft > 8)
		return -1;

	bits = amr_ft_len_bits[ft];
	bytes = bits / 8;
	if (bits % 8)
		bytes++;

	return bytes;
}

static void
dissect_urtp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *urtp_tree      = NULL;
	gboolean    marker_set = 0;
	unsigned int payload_type;
	gchar *payload_type_str = NULL;
	unsigned int offset = 0;
	guint8     timestamp, sync_src, num_frames;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "uRTP");

	timestamp = tvb_get_guint8(tvb, offset);
	sync_src = tvb_get_guint8(tvb, offset+1);
	payload_type = tvb_get_guint8(tvb, offset+2) & 0xF;
	num_frames = tvb_get_guint8(tvb, offset+2) >> 4;

	col_add_fstr( pinfo->cinfo, COL_INFO,
	    "PT=%s, SSRC=0x%X, Time=%u%s",
		payload_type_str ? payload_type_str : val_to_str_ext( payload_type, &urtp_payload_type_vals_ext,"Unknown (%u)" ),
	    sync_src,
	    timestamp,
	    marker_set ? ", Mark " : " ");


	if ( tree ) {
		unsigned int i;
		/* Create RTP protocol tree */
		ti = proto_tree_add_item(tree, proto_urtp, tvb, offset, -1, FALSE );
		urtp_tree = proto_item_add_subtree(ti, ett_urtp );

		proto_tree_add_item( urtp_tree, hf_urtp_timestamp, tvb,
		    offset, 1, FALSE );
		proto_tree_add_item( urtp_tree, hf_urtp_ssrc, tvb,
		    offset+1, 1, FALSE );
		proto_tree_add_item( urtp_tree, hf_urtp_payload_type, tvb,
		    offset+2, 1, FALSE );
		proto_tree_add_item( urtp_tree, hf_urtp_num_frames, tvb,
		    offset+2, 1, FALSE );

		offset += 3;

		for (i = 0; i < num_frames; i++) {
			guint8 oct1, ft;
			tvbuff_t *subtvb;
			int frame_len;

			oct1 = tvb_get_guint8(tvb, offset+1);
			ft = (oct1 >> 3) & 0xF;
			frame_len = amr_bytelen_padded(ft);
			if (frame_len < 0)
				return;

			subtvb = tvb_new_subset(tvb, offset, frame_len+2, frame_len+2);
			call_dissector(amr_handle, subtvb, pinfo, urtp_tree);

			offset += frame_len+2;
		}
	}

	if (!pinfo->flags.in_error_pkt)
		tap_queue_packet(urtp_tap, pinfo, NULL);
}

/* Register uRTP */

void
proto_register_urtp(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_urtp_timestamp,
			{
				"Timestamp",
				"urtp.timestamp",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0xFF,
				NULL, HFILL
			}
		},
		{
			&hf_urtp_ssrc,
			{
				"SSRC",
				"urtp.ssrc",
				FT_UINT8,
				BASE_HEX,
				NULL,
				0xFF,
				NULL, HFILL
			}
		},
		{
			&hf_urtp_payload_type,
			{
				"Payload Type",
				"urtp.payload_type",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0F,
				NULL, HFILL
			}
		},
		{
			&hf_urtp_num_frames,
			{
				"Number of frames to follow",
				"urtp.number_samples",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0xF0,
				NULL, HFILL
			}
		},
		{
			&hf_urtp_data,
			{
				"Payload",
				"urtp.payload",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
	};

	static gint *ett[] =
	{
		&ett_urtp,
	};

	proto_urtp = proto_register_protocol("Micro Real-Time Transport Protocol",
					    "uRTP", "urtp");
	proto_register_field_array(proto_urtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("urtp", dissect_urtp, proto_urtp);

	urtp_tap = register_tap("urtp");
}

void
proto_reg_handoff_urtp(void)
{
	static gboolean urtp_prefs_initialized = FALSE;

	if (!urtp_prefs_initialized) {
		urtp_handle = find_dissector("urtp");

		dissector_add_handle("udp.port", urtp_handle);  /* for 'decode-as' */
		//heur_dissector_add( "udp", dissect_urtp_heur, proto_urtp);

		data_handle = find_dissector("data");
		amr_handle = find_dissector("amr");

		urtp_prefs_initialized = TRUE;
	}
}

/*
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * tab-width: 8
 * End:
 */
