/* packet-sna.h
 * Definitions for SNA dissection.
 *
 * $Id: packet-sna.h,v 1.6 2003/08/26 01:00:28 guy Exp $
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

#ifndef __PACKET_SNA_H__
#define __PACKET_SNA_H__

/*
 * Structure used to represent an FID Type 4 address; gives the layout of the
 * data pointed to by an AT_SNA "address" structure if the size is
 * SNA_FID_TYPE_4_ADDR_LEN.
 */
#define	SNA_FID_TYPE_4_ADDR_LEN	6
struct sna_fid_type_4_addr {
	guint32	saf;
	guint16	ef;
};

#endif
