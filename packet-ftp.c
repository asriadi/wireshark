/* packet-ftp.c
 * Routines for ftp packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * Copyright 2001, Juan Toledo <toledo@users.sourceforge.net> (Passive FTP)
 * 
 * $Id: packet-ftp.c,v 1.30 2001/06/18 02:17:46 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include "packet.h"
#include "strutil.h"
#include "conversation.h"

static int proto_ftp = -1;
static int proto_ftp_data = -1;
static int hf_ftp_response = -1;
static int hf_ftp_request = -1;
static int hf_ftp_request_command = -1;
static int hf_ftp_request_data = -1;
static int hf_ftp_response_code = -1;
static int hf_ftp_response_data = -1;

static gint ett_ftp = -1;
static gint ett_ftp_data = -1;

#define TCP_PORT_FTPDATA		20
#define TCP_PORT_FTP			21

static void
dissect_ftpdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_ftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gboolean        is_request;
        proto_tree      *ftp_tree;
	proto_item	*ti;
	gint		offset = 0;
	const u_char	*line;
	guint16		passive_port = 0;
	gint		next_offset;
	int		linelen;
	int		tokenlen;
	const u_char	*next_token;

	if (pinfo->match_port == pinfo->destport)
		is_request = TRUE;
	else
		is_request = FALSE;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "FTP");

	/*
	 * Find the end of the first line.
	 *
	 * Note that "tvb_find_line_end()" will return a value that is
	 * not longer than what's in the buffer, so the "tvb_get_ptr()"
	 * call won't throw an exception.
	 */
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset);
	line = tvb_get_ptr(tvb, offset, linelen);

	if (check_col(pinfo->fd, COL_INFO)) {
		/*
		 * Put the first line from the buffer into the summary
		 * (but leave out the line terminator).
		 */
		col_add_fstr(pinfo->fd, COL_INFO, "%s: %s",
		    is_request ? "Request" : "Response",
		    format_text(line, linelen));
	}
   
	/*
	 * Check for passive ftp response. Such response is in the form
	 * 227 some_text (a,b,c,d,p1,p2) , where a.b.c.d is the IP address
	 * of the server, and p1, p2 are the hi and low bytes of the tcp
	 * port the server will open for the client to connect to.
	 */
	tokenlen = get_token_len(line, line + linelen, &next_token);
	if (tokenlen!=0 && !strcmp ("227", format_text (line, tokenlen)))
	  {
		u_char          *token;
		gint		hi_byte;
		gint		low_byte;
		guint8 		i;
		  
		strtok (format_text(line, linelen), "(,)");
		for (i = 1; i <= 4; i++)
	          strtok (NULL, "(,)");
		  
		if ( (token = strtok (NULL, "(,)")) && sscanf (token, "%d", &hi_byte)
		  && (token = strtok (NULL, "(,)")) && sscanf (token, "%d", &low_byte) )
		  passive_port = hi_byte * 256 + low_byte;
	  }
	
	/*
	 * If a passive response has been found and a conversation,
	 * was not registered already, register the new conversation
	 * and dissector
	 */
	if (passive_port && !find_conversation(&pinfo->src, &pinfo->dst, PT_TCP,
					       passive_port, 0, NO_PORT_B))
	  {
		conversation_t 	*conversation;
		  
		conversation = conversation_new(&pinfo->src, &pinfo->dst, PT_TCP,
						  passive_port, 0, NULL,
						  NO_PORT2);
		conversation_set_dissector(conversation, dissect_ftpdata);

	  }

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ftp, tvb, offset,
		    tvb_length_remaining(tvb, offset), FALSE);
		ftp_tree = proto_item_add_subtree(ti, ett_ftp);

		if (is_request) {
			proto_tree_add_boolean_hidden(ftp_tree,
			    hf_ftp_request, tvb, 0, 0, TRUE);
			proto_tree_add_boolean_hidden(ftp_tree,
			    hf_ftp_response, tvb, 0, 0, FALSE);
		} else {
			proto_tree_add_boolean_hidden(ftp_tree,
			    hf_ftp_request, tvb, 0, 0, FALSE);
			proto_tree_add_boolean_hidden(ftp_tree,
			    hf_ftp_response, tvb, 0, 0, TRUE);
		}

		/*
		 * Extract the first token, and, if there is a first
		 * token, add it as the request or reply code.
		 */
		tokenlen = get_token_len(line, line + linelen, &next_token);
		if (tokenlen != 0) {
			if (is_request) {
				proto_tree_add_string_format(ftp_tree,
				    hf_ftp_request_command, tvb, offset,
				    tokenlen, line, "Request: %s",
				    format_text(line, tokenlen));
			} else {
				proto_tree_add_uint_format(ftp_tree,
				    hf_ftp_response_code, tvb, offset,
				    tokenlen, atoi(line), "Response: %s",
				    format_text(line, tokenlen));
			}
			offset += next_token - line;
			linelen -= next_token - line;
			line = next_token;
		}

		/*
		 * Add the rest of the first line as request or
		 * reply data.
		 */
		if (linelen != 0) {
			if (is_request) {
				proto_tree_add_string_format(ftp_tree,
				    hf_ftp_request_data, tvb, offset,
				    linelen, line, "Request Arg: %s",
				    format_text(line, linelen));
			} else {
				proto_tree_add_string_format(ftp_tree,
				    hf_ftp_response_data, tvb, offset,
				    linelen, line, "Response Arg: %s",
				    format_text(line, linelen));
			}
		}
		offset = next_offset;

		/*
		 * Show the rest of the request or response as text,
		 * a line at a time.
		 */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * Find the end of the line.
			 */
			linelen = tvb_find_line_end(tvb, offset, -1,
			    &next_offset);

			/*
			 * Put this line.
			 */
			proto_tree_add_text(ftp_tree, tvb, offset,
			    next_offset - offset, "%s",
			    tvb_format_text(tvb, offset, next_offset - offset));
			offset = next_offset;
		}
	}
}

static void
dissect_ftpdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_tree      *ti, *ftp_data_tree;
        int		data_length;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "FTP-DATA");

	if (check_col(pinfo->fd, COL_INFO)) {
		col_add_fstr(pinfo->fd, COL_INFO, "FTP Data: %u bytes",
		    tvb_length(tvb));
	}

	if (tree) {
		data_length = tvb_length(tvb);

		ti = proto_tree_add_item(tree, proto_ftp_data, tvb, 0,
		    data_length, FALSE);
		ftp_data_tree = proto_item_add_subtree(ti, ett_ftp_data);

		/*
		 * XXX - if this is binary data, it'll produce
		 * a *really* long line.
		 */
		proto_tree_add_text(ftp_data_tree, tvb, 0, data_length,
		    "FTP Data: %s", tvb_format_text(tvb, 0, data_length));
	}
}

void
proto_register_ftp(void)
{
    static hf_register_info hf[] = {
    { &hf_ftp_response,
      { "Response",           "ftp.response",
      	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if FTP response", HFILL }},

    { &hf_ftp_request,
      { "Request",            "ftp.request",
      	FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      	"TRUE if FTP request", HFILL }},

    { &hf_ftp_request_command,
      { "Request command",    "ftp.request.command",
      	FT_STRING,  BASE_NONE, NULL, 0x0,
      	"", HFILL }},

    { &hf_ftp_request_data,
      { "Request data",	      "ftp.request.data",
      	FT_STRING,  BASE_NONE, NULL, 0x0,
      	"", HFILL }},

    { &hf_ftp_response_code,
      { "Response code",      "ftp.response.code",
      	FT_UINT8,   BASE_DEC, NULL, 0x0,
      	"", HFILL }},

    { &hf_ftp_response_data,
      { "Response data",      "ftp.reponse.data",
      	FT_STRING,  BASE_NONE, NULL, 0x0,
      	"", HFILL }}
  };
  static gint *ett[] = {
    &ett_ftp,
    &ett_ftp_data,
  };

  proto_ftp = proto_register_protocol("File Transfer Protocol (FTP)", "FTP",
				      "ftp");
  proto_ftp_data = proto_register_protocol("FTP Data", "FTP-DATA", "ftp-data");
  proto_register_field_array(proto_ftp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ftp(void)
{
  dissector_add("tcp.port", TCP_PORT_FTPDATA, &dissect_ftpdata, proto_ftp_data);
  dissector_add("tcp.port", TCP_PORT_FTP, &dissect_ftp, proto_ftp_data);
}
