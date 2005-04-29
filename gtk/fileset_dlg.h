/* fileset_dlg.h
 * Definitions for the fileset dialog box
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __FILESET_DLG_H__
#define __FILESET_DLG_H__


/* start getting stats from all files */
extern void fileset_cb(GtkWidget *w, gpointer d);

extern void fileset_next_cb(GtkWidget *w, gpointer d);

extern void fileset_previous_cb(GtkWidget *w, gpointer d);

#endif /* fileset_dlg.h */
