/* new_packet_list.c
 * Routines to implement a new GTK2 packet list using our custom model
 * Copyright 2008-2009, Stephen Fisher (see AUTHORS file)
 * Co-authors Anders Broman, Kovarththanan Rajaratnam and Stig Bjorlykke.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef NEW_PACKET_LIST

#include "string.h"

#include <stdio.h>
#include <gtk/gtk.h>
#include <glib.h>

#include "gui_utils.h"
#include "packet_list_store.h"
#include "gtk/new_packet_list.h"
#include "epan/column_info.h"
#include "epan/prefs.h"
#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include "../ui_util.h"
#include "../progress_dlg.h"
#include "../simple_dialog.h"
#include "epan/emem.h"
#include "globals.h"
#include "gtk/gtkglobals.h"
#include "gtk/font_utils.h"
#include "gtk/packet_history.h"
#include "epan/column.h"
#include "gtk/recent.h"
#include "gtk/keys.h"
#include "gtk/menus.h"
#include "color.h"
#include "color_filters.h"
#include "gtk/color_utils.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/main_statusbar.h"
#include "gtk/packet_win.h"
#include "gtk/main.h"
#include "gtk/prefs_column.h"
#include "gtk/prefs_dlg.h"
#include "gtk/dlg_utils.h"

#define COLUMN_WIDTH_MIN 40

static PacketList *packetlist;
static gboolean last_at_end = FALSE;
static gboolean enable_color;

static GtkWidget *create_view_and_model(void);
static void scroll_to_and_select_iter(GtkTreeModel *model, GtkTreeSelection *selection, GtkTreeIter *iter);
static void new_packet_list_select_cb(GtkTreeView *tree_view, gpointer data _U_);
static void new_packet_list_double_click_cb(GtkTreeView *treeview,
					    GtkTreePath *path,
					    GtkTreeViewColumn *col _U_,
					    gpointer userdata _U_);
static void show_cell_data_func(GtkTreeViewColumn *col,
				GtkCellRenderer *renderer,
				GtkTreeModel *model,
				GtkTreeIter *iter,
				gpointer data);
static gint row_number_from_iter(GtkTreeIter *iter);

void new_packet_list_set_sel_browse(gboolean val, gboolean force_set);

GtkWidget *
new_packet_list_create(void)
{
	GtkWidget *view, *scrollwin;

	scrollwin = scrolled_window_new(NULL, NULL);

	view = create_view_and_model();

	new_packet_list_set_sel_browse(prefs.gui_plist_sel_browse, FALSE);

	gtk_container_add(GTK_CONTAINER(scrollwin), view);

	g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY, view);

	return scrollwin;
}

/* XXX - implement a smarter solution for recreating the packet list */
void
new_packet_list_recreate(void)
{
	gtk_widget_destroy(pkt_scrollw);

	prefs.num_cols = g_list_length(prefs.col_list);

	build_column_format_array(&cfile.cinfo, prefs.num_cols, FALSE);

	pkt_scrollw = new_packet_list_create();
	gtk_widget_show_all(pkt_scrollw);

	main_widgets_rearrange();

	if(cfile.state != FILE_CLOSED)
		redissect_packets();
}

guint
new_packet_list_append(column_info *cinfo _U_, frame_data *fdata, packet_info *pinfo _U_)
{
	/* fdata should be filled with the stuff we need
	 * strings are built at display time.
	 */

	/* Return the _visible_ position */
	return packet_list_append_record(packetlist, fdata);
}

static gboolean
right_justify_column (gint col)
{
	header_field_info *hfi;
	gboolean right_justify = FALSE;

	switch (cfile.cinfo.col_fmt[col]) {

	case COL_NUMBER:
	case COL_PACKET_LENGTH:
	case COL_CUMULATIVE_BYTES:
		right_justify = TRUE;
		break;

	case COL_CUSTOM:
		hfi = proto_registrar_get_byname(cfile.cinfo.col_custom_field[col]);
		/* Check if this is a valid field and we have no strings lookup table */
		if ((hfi != NULL) && (hfi->strings == NULL)) {
			/* Check for bool, framenum and decimal/octal integer types */
			if ((hfi->type == FT_BOOLEAN) || (hfi->type == FT_FRAMENUM) ||
				(((hfi->display == BASE_DEC) || (hfi->display == BASE_OCT)) &&
				 (IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type)))) {
				right_justify = TRUE;
			}
		}
		break;

	default:
		break;
	}

	return right_justify;
}

static void
col_title_change_ok (GtkWidget *w, gpointer parent_w)
{
	GtkTreeViewColumn *col = g_object_get_data (G_OBJECT(w), "column");
	gint col_id = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(col), E_MPACKET_LIST_COL_KEY));
	GtkWidget *entry = g_object_get_data (G_OBJECT(w), "entry");
	const gchar *title =  gtk_entry_get_text(GTK_ENTRY(entry));
	gint col_width;

	gtk_tree_view_column_set_title(col, title);
	column_prefs_rename(col_id, title);

	col_width = get_default_col_size (packetlist->view, title);
	gtk_tree_view_column_set_min_width(col, col_width);
	new_packet_list_resize_column (col_id);

	if (!prefs.gui_use_pref_save) {
		prefs_main_write();
	}

	window_destroy(GTK_WIDGET(parent_w));
}

static void
col_title_change_cancel (GtkWidget *w _U_, gpointer parent_w)
{
	window_destroy(GTK_WIDGET(parent_w));
}

static void 
col_title_edit_dlg (GtkTreeViewColumn *col)
{
	const gchar *value = gtk_tree_view_column_get_title(col);

	GtkWidget *win, *main_tb, *main_vb, *bbox, *cancel_bt, *ok_bt;
	GtkWidget *entry, *label;

	win = dlg_window_new("Column Title");

	gtk_window_set_resizable(GTK_WINDOW(win),FALSE);
	gtk_window_resize(GTK_WINDOW(win), 400, 100);

	main_vb = gtk_vbox_new(FALSE, 5);
	gtk_container_add(GTK_CONTAINER(win), main_vb);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 6);

	main_tb = gtk_table_new(2, 2, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 10);

	label = gtk_label_new(ep_strdup_printf("Title:"));
	gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 1, 2);
	gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);

	entry = gtk_entry_new();
	gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2, 1, 2);
	gtk_entry_set_text(GTK_ENTRY(entry), value);

	bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_OK, NULL);
	gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

	ok_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
	g_object_set_data (G_OBJECT(ok_bt), "column", col);
	g_object_set_data (G_OBJECT(ok_bt), "entry", entry);
	g_signal_connect(ok_bt, "clicked", G_CALLBACK(col_title_change_ok), win);

	dlg_set_activate(entry, ok_bt);

	cancel_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	g_signal_connect(cancel_bt, "clicked", G_CALLBACK(col_title_change_cancel), win);
	window_set_cancel_button(win, cancel_bt, NULL);

	gtk_widget_grab_default(ok_bt);
	gtk_widget_show_all(win);
}

static void
new_packet_list_sort_column (gint col_id, GtkTreeViewColumn *col, GtkSortType order)
{
	GtkTreeViewColumn *prev_col = (GtkTreeViewColumn *) 
	  g_object_get_data(G_OBJECT(packetlist->view), E_MPACKET_LIST_PREV_COLUMN_KEY);

	if (prev_col) {
		gtk_tree_view_column_set_sort_indicator(prev_col, FALSE);
	}
	gtk_tree_view_column_set_sort_indicator(col, TRUE);
	gtk_tree_view_column_set_sort_order (col, order);
	g_object_set_data(G_OBJECT(packetlist->view), E_MPACKET_LIST_PREV_COLUMN_KEY, col);
	gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(packetlist), col_id, order);
}

/* 
 * We have our own functionality to toggle sort order on a column to avoid
 * having empty sorting arrow widgets in the column header.
 */
static void
new_packet_list_column_clicked_cb (GtkTreeViewColumn *col, gpointer user_data _U_)
{
	GtkSortType order = gtk_tree_view_column_get_sort_order (col);
	gint col_id = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(col), E_MPACKET_LIST_COL_KEY));

	if (!gtk_tree_view_column_get_sort_indicator(col)) {
		new_packet_list_sort_column (col_id, col, GTK_SORT_ASCENDING);
	} else if (order == GTK_SORT_ASCENDING) {
		new_packet_list_sort_column (col_id, col, GTK_SORT_DESCENDING);
	} else {
		gtk_tree_view_column_set_sort_indicator(col, FALSE);
		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(packetlist), 0, GTK_SORT_ASCENDING);
	}
}

static gdouble
get_xalign_value (gchar xalign, gboolean right_justify)
{
	double value;

	switch (xalign) {
	case COLUMN_XALIGN_RIGHT:
		value = 1.0f;
		break;
	case COLUMN_XALIGN_CENTER:
		value = 0.5f;
		break;
	case COLUMN_XALIGN_LEFT:
		value = 0.0f;
		break;
	case COLUMN_XALIGN_DEFAULT:
	default:
		if (right_justify) {
			value = 1.0f;
		} else {
			value = 0.0f;
		}
		break;
	}

	return value;
}

static void
new_packet_list_xalign_column (gint col_id, GtkTreeViewColumn *col, gchar xalign)
{
#if GTK_CHECK_VERSION(2,18,0)
	GList *renderers = gtk_cell_layout_get_cells (GTK_CELL_LAYOUT(col));
#else
	GList *renderers = gtk_tree_view_column_get_cell_renderers (col);
#endif
	gboolean right_justify = right_justify_column(col_id);
	gdouble value = get_xalign_value (xalign, right_justify);
	GList *entry;
	GtkCellRenderer *renderer;

	entry = g_list_first(renderers);
	while (entry) {
		renderer = (GtkCellRenderer *)entry->data;
		g_object_set(G_OBJECT(renderer), "xalign", value, NULL);
		entry = g_list_next (entry);
	}
	g_list_free (renderers);

	if ((xalign == COLUMN_XALIGN_LEFT && !right_justify) ||
	    (xalign == COLUMN_XALIGN_RIGHT && right_justify)) {
		/* Default value selected, save default in the recent settings */
		xalign = COLUMN_XALIGN_DEFAULT;
	}

	recent_set_column_xalign (col_id, xalign);
	gtk_widget_queue_draw (packetlist->view);
}

static void
new_packet_list_remove_column (gint col_id, GtkTreeViewColumn *col _U_)
{
	column_prefs_remove(col_id);

	if (!prefs.gui_use_pref_save) {
		prefs_main_write();
	}

	new_packet_list_recreate();
}

void
new_packet_list_column_menu_cb (GtkWidget *w _U_, gpointer user_data _U_, COLUMN_SELECTED_E action)
{
	GtkTreeViewColumn *col = (GtkTreeViewColumn *)
	  g_object_get_data(G_OBJECT(packetlist->view), E_MPACKET_LIST_COLUMN_KEY);
	gint col_id = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(col), E_MPACKET_LIST_COL_KEY));

	switch (action) {
	case COLUMN_SELECTED_SORT_ASCENDING:
		new_packet_list_sort_column (col_id, col, GTK_SORT_ASCENDING);
		break;
	case COLUMN_SELECTED_SORT_DESCENDING:
		new_packet_list_sort_column (col_id, col, GTK_SORT_DESCENDING);
		break;
	case COLUMN_SELECTED_SORT_NONE:
		gtk_tree_view_column_set_sort_indicator(col, FALSE);
		gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(packetlist), 0, GTK_SORT_ASCENDING);
		break;
	case COLUMN_SELECTED_ALIGN_LEFT:
		new_packet_list_xalign_column (col_id, col, COLUMN_XALIGN_LEFT);
		break;
	case COLUMN_SELECTED_ALIGN_CENTER:
		new_packet_list_xalign_column (col_id, col, COLUMN_XALIGN_CENTER);
		break;
	case COLUMN_SELECTED_ALIGN_RIGHT:
		new_packet_list_xalign_column (col_id, col, COLUMN_XALIGN_RIGHT);
		break;
	case COLUMN_SELECTED_ALIGN_DEFAULT:
		new_packet_list_xalign_column (col_id, col, COLUMN_XALIGN_DEFAULT);
		break;
	case COLUMN_SELECTED_RESIZE:
		new_packet_list_resize_column (col_id);
		break;
	case COLUMN_SELECTED_RENAME:
		col_title_edit_dlg (col);
		break;
	case COLUMN_SELECTED_REMOVE:
		new_packet_list_remove_column (col_id, col);
		break;
	default:
		g_assert_not_reached();
		break;
	}
}

static void
new_packet_list_column_button_pressed_cb (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	GtkWidget *col = (GtkWidget *) data;
	GtkWidget *menu = g_object_get_data(G_OBJECT(popup_menu_object), PM_PACKET_LIST_COL_KEY);
	gint       col_id = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(col), E_MPACKET_LIST_COL_KEY));
	gboolean   right_justify = right_justify_column (col_id);

	menus_set_column_align_default (right_justify);
	g_object_set_data(G_OBJECT(packetlist->view), E_MPACKET_LIST_COLUMN_KEY, col);
	popup_menu_handler (widget, event, menu);
}

static GtkWidget *
create_view_and_model(void)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	gint i, col_width;
	gdouble value;
	gchar *tooltip_text;
	header_field_info *hfi;
	gint col_min_width;
	GtkTooltips *tooltips = gtk_tooltips_new ();

	packetlist = new_packet_list_new();

	packetlist->view = tree_view_new(GTK_TREE_MODEL(packetlist));

#if GTK_CHECK_VERSION(2,6,0)
	gtk_tree_view_set_fixed_height_mode(GTK_TREE_VIEW(packetlist->view),
						TRUE);
#endif
	g_signal_connect(packetlist->view, "cursor-changed",
			 G_CALLBACK(new_packet_list_select_cb), NULL);
	g_signal_connect(packetlist->view, "row-activated",
			 G_CALLBACK(new_packet_list_double_click_cb),
			 g_object_get_data(G_OBJECT(popup_menu_object),
					   PM_PACKET_LIST_KEY));
	g_signal_connect(packetlist->view, "button_press_event", G_CALLBACK(popup_menu_handler),
				   g_object_get_data(G_OBJECT(popup_menu_object), PM_PACKET_LIST_KEY));
	g_object_set_data(G_OBJECT(popup_menu_object), E_MPACKET_LIST_KEY, packetlist);

	/*		g_object_unref(packetlist); */ /* Destroy automatically with view for now */ /* XXX - Messes up freezing & thawing */

	gtk_widget_modify_font(packetlist->view, user_font_get_regular());


	/* We need one extra column to store the entire PacketListRecord */
	for(i = 0; i < cfile.cinfo.num_cols; i++) {
		renderer = gtk_cell_renderer_text_new();
		col = gtk_tree_view_column_new();
		gtk_tree_view_column_pack_start(col, renderer, TRUE);
		value = get_xalign_value(recent_get_column_xalign(i), right_justify_column(i));
		g_object_set(G_OBJECT(renderer), 
			     "xalign", value, 
			     NULL);
		g_object_set(renderer,
			     "ypad", 0,
			     NULL);
		gtk_tree_view_column_set_cell_data_func(col, renderer,
							show_cell_data_func,
							GINT_TO_POINTER(i),
							NULL);
		if (cfile.cinfo.col_fmt[i] == COL_CUSTOM) {
			hfi = proto_registrar_get_byname(cfile.cinfo.col_custom_field[i]);
			/* Check if this is a valid custom_field */
			if (hfi != NULL) {
				if (hfi->parent != -1) {
					/* Prefix with protocol name */
					tooltip_text = g_strdup_printf("%s\n%s (%s)", proto_get_protocol_name(hfi->parent), hfi->name, hfi->abbrev);
				} else {
					tooltip_text = g_strdup_printf("%s (%s)", hfi->name, hfi->abbrev);
				}
                	} else {
				/* XXX - include custom_field value? e.g. "Unknown Custom (foo.bar)" */
				tooltip_text = g_strdup_printf("Unknown Custom Column Field");
			}	
		} else {
			tooltip_text = g_strdup(col_format_desc(cfile.cinfo.col_fmt[i]));
		}
		gtk_tree_view_column_set_title(col, cfile.cinfo.col_title[i]);
		gtk_tree_view_column_set_clickable(col, TRUE);
		gtk_tree_view_column_set_resizable(col, TRUE);
		gtk_tree_view_column_set_sizing(col,GTK_TREE_VIEW_COLUMN_FIXED);
		gtk_tree_view_column_set_reorderable(col, TRUE); /* XXX - Should this be saved in the prefs? */

		g_object_set_data(G_OBJECT(col), E_MPACKET_LIST_COL_KEY, GINT_TO_POINTER(i));
		g_signal_connect(col, "clicked", G_CALLBACK(new_packet_list_column_clicked_cb), NULL);

		/* 
		 * The column can't be adjusted to a size smaller than this
		 * XXX The minimum size will be the size of the title
		 * should that be limited for long titles?
		 */
		col_min_width = get_default_col_size (packetlist->view, cfile.cinfo.col_title[i]);
		if(col_min_width<COLUMN_WIDTH_MIN){
			gtk_tree_view_column_set_min_width(col, COLUMN_WIDTH_MIN);
		}else{
			gtk_tree_view_column_set_min_width(col, col_min_width);
		}

		/* Set the size the column will be displayed with */
		col_width = recent_get_column_width(i);
		if(col_width < 1) {
			gint fmt;
			const gchar *long_str;

			fmt = get_column_format(i);
			long_str = get_column_width_string(fmt, i);
			if(long_str){
				col_width = get_default_col_size (packetlist->view, long_str);
			}else{
				col_width = COLUMN_WIDTH_MIN;
			}
			gtk_tree_view_column_set_fixed_width(col, col_width);
		}else{
			gtk_tree_view_column_set_fixed_width(col, col_width);
		}
		gtk_tree_view_append_column(GTK_TREE_VIEW(packetlist->view), col);

		/* XXX Breaks the GTK+ API, but this is the only way to attach a signal to
		 * a GtkTreeView column header. See GTK bug #141937.
		 */
		gtk_tooltips_set_tip(tooltips, col->button, tooltip_text, NULL);
		g_free(tooltip_text);
		g_signal_connect(col->button, "button_press_event", 
				 G_CALLBACK(new_packet_list_column_button_pressed_cb), col);

		if (i == 0) {  /* Default sort on first column */
			g_object_set_data(G_OBJECT(packetlist->view), E_MPACKET_LIST_COLUMN_KEY, col);
			g_object_set_data(G_OBJECT(packetlist->view), E_MPACKET_LIST_PREV_COLUMN_KEY, col);
		}
	}

	return packetlist->view;
}

static PacketListRecord *
new_packet_list_get_record(GtkTreeModel *model, GtkTreeIter *iter)
{
	PacketListRecord *record;
	/* The last column is reserved for the entire PacketListRecord */
	gint record_column = gtk_tree_model_get_n_columns(model)-1;

	gtk_tree_model_get(model, iter,
			   record_column,
			   &record,
			   -1);

	return record;
}

void
new_packet_list_clear(void)
{
	packet_history_clear();

	new_packet_list_store_clear(packetlist);
	gtk_widget_queue_draw(packetlist->view);
	/* XXX is this correct in all cases?
	 * Reset the sort column, use packetlist as model in case the list is frozen.
	 */
	gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(packetlist),
			0, GTK_SORT_ASCENDING);

}

void
new_packet_list_freeze(void)
{
	/* So we don't lose the model by the time we want to thaw it */
	g_object_ref(packetlist);

	/* Detach view from model */
	gtk_tree_view_set_model(GTK_TREE_VIEW(packetlist->view), NULL);
}

void
new_packet_list_thaw(void)
{
	GtkTreePath *path;
	GtkTreeSelection *selection;
	GtkTreeIter iter;

	/* Apply model */
	gtk_tree_view_set_model( GTK_TREE_VIEW(packetlist->view), GTK_TREE_MODEL(packetlist));

	/* Remove extra reference added by new_packet_list_freeze() */
	g_object_unref(packetlist);

	/* Selection may have been lost, reselect the current row */
	if (cfile.current_row!=0){
		path = gtk_tree_path_new_from_indices(cfile.current_row-1, -1);

		if (gtk_tree_model_get_iter(gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view)), &iter, path)){
			/* Select the row */
			selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
			gtk_tree_selection_select_iter (selection, &iter);
		}
	}

	packets_bar_update();
}

void
new_packet_list_recreate_visible_rows(void)
{

	packet_list_recreate_visible_rows(packetlist);

}

void new_packet_list_resize_column(gint col)
{
	GtkTreeViewColumn *column;
	gint col_width;
	const gchar *long_str;

	long_str = packet_list_get_widest_column_string(packetlist, col);
	if(!long_str || strcmp("",long_str)==0)
		/* If we get an empty string leave the width unchanged */
		return;
	column = gtk_tree_view_get_column (GTK_TREE_VIEW(packetlist->view), col);
	col_width = get_default_col_size (packetlist->view, long_str);
	gtk_tree_view_column_set_fixed_width(column, col_width);
}

static void
new_packet_list_resize_columns(void)
{
	gint		progbar_loop_max;
	gint		progbar_loop_var;

	progbar_loop_max = cfile.cinfo.num_cols;

	for (progbar_loop_var = 0; progbar_loop_var < progbar_loop_max; ++progbar_loop_var)
		new_packet_list_resize_column(progbar_loop_var);
}

void
new_packet_list_resize_columns_cb(GtkWidget *widget _U_, gpointer data _U_)
{
	new_packet_list_resize_columns();
}

void
new_packet_list_next(void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkWidget *focus = gtk_window_get_focus(GTK_WINDOW(top_level));

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	/* model is filled with the current model as a convenience. */
	if (!gtk_tree_selection_get_selected(selection, &model, &iter))
		return;

	if (!gtk_tree_model_iter_next(model, &iter))
		return;

	scroll_to_and_select_iter(model, selection, &iter);

	/* Set the focus back where it was */
	if (focus)
		gtk_window_set_focus(GTK_WINDOW(top_level), focus);
}

void
new_packet_list_prev(void)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkWidget *focus = gtk_window_get_focus(GTK_WINDOW(top_level));

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	/* model is filled with the current model as a convenience. */
	if (!gtk_tree_selection_get_selected(selection, &model, &iter))
		return;

	path = gtk_tree_model_get_path(model, &iter);

	if (!gtk_tree_path_prev(path))
		return;

	if (!gtk_tree_model_get_iter(model, &iter, path))
		return;

	scroll_to_and_select_iter(model, selection, &iter);

	gtk_tree_path_free(path);

	/* Set the focus back where it was */
	if (focus)
		gtk_window_set_focus(GTK_WINDOW(top_level), focus);
}

static void
scroll_to_and_select_iter(GtkTreeModel *model, GtkTreeSelection *selection, GtkTreeIter *iter)
{
	GtkTreePath *path;

	g_assert(model);

	/* Select the row */
	if(!selection)
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	gtk_tree_selection_select_iter (selection, iter);
	path = gtk_tree_model_get_path(model, iter);
	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			TRUE,	/* use_align */
			0.5,	/* row_align determines where the row is placed, 0.5 means center */
			0); 	/* The horizontal alignment of the column */
	gtk_tree_view_set_cursor(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			FALSE); /* start_editing */

	/* Needed to get the middle and bottom panes updated */
	new_packet_list_select_cb(GTK_TREE_VIEW(packetlist->view), NULL);

	gtk_tree_path_free(path);
}

void
new_packet_list_select_first_row(void)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;

	if(!gtk_tree_model_get_iter_first(model, &iter))
		return;

	scroll_to_and_select_iter(model, NULL, &iter);
	gtk_widget_grab_focus(packetlist->view);
}

void
new_packet_list_select_last_row(void)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;
	gint children;
	guint last_row;

	if((children = gtk_tree_model_iter_n_children(model, NULL)) == 0)
		return;

	last_row = children-1;
	if(!gtk_tree_model_iter_nth_child(model, &iter, NULL, last_row))
		return;

	scroll_to_and_select_iter(model, NULL, &iter);
}

void
new_packet_list_moveto_end(void)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;
	GtkTreePath *path;
	gint children;
	guint last_row;

	if((children = gtk_tree_model_iter_n_children(model, NULL)) == 0)
		return;

	last_row = children-1;
	if(!gtk_tree_model_iter_nth_child(model, &iter, NULL, last_row))
		return;

	path = gtk_tree_model_get_path(model, &iter);

	gtk_tree_view_scroll_to_cell(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			TRUE,	/* use_align */
			0.5,	/* row_align determines where the row is placed, 0.5 means center */
			0); 	/* The horizontal alignment of the column */

	gtk_tree_path_free(path);

}

gboolean
new_packet_list_check_end(void)
{
	gboolean at_end = FALSE;
	GtkAdjustment *adj;

	adj = gtk_tree_view_get_vadjustment(GTK_TREE_VIEW(packetlist->view));
	g_return_val_if_fail(adj != NULL, FALSE);

	if (adj->value >= adj->upper - adj->page_size) {
		at_end = TRUE;
	}
#ifdef HAVE_LIBPCAP
	if (adj->value > 0 && at_end != last_at_end && at_end != auto_scroll_live) {
		menu_auto_scroll_live_changed(at_end);
	}
#endif
	last_at_end = at_end;
	return at_end;
}

gint
new_packet_list_find_row_from_data(gpointer data, gboolean select)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;
	frame_data *fdata_needle = data;

	/* Initializes iter with the first iterator in the tree (the one at the path "0")
	 * and returns TRUE. Returns FALSE if the tree is empty
	 */
	if(!gtk_tree_model_get_iter_first(model, &iter))
		return -1;

	do {
		PacketListRecord *record;
		frame_data *fdata;

		record = new_packet_list_get_record(model, &iter);
		fdata = record->fdata;

		if(fdata == fdata_needle) {
			if(select)
				scroll_to_and_select_iter(model, NULL, &iter);

			return fdata->num;
		}
	} while (gtk_tree_model_iter_next(model, &iter));

	return -1;
}

void
new_packet_list_set_selected_row(gint row)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreeIter iter;
	GtkTreeSelection *selection;
	GtkTreePath *path;

	path = gtk_tree_path_new_from_indices(row-1, -1);

	if (!gtk_tree_model_get_iter(model, &iter, path))
		return;

	/* Select the row */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	gtk_tree_selection_select_iter (selection, &iter);
	gtk_tree_view_set_cursor(GTK_TREE_VIEW(packetlist->view),
			path,
			NULL,
			FALSE); /* start_editing */

	/* Needed to get the middle and bottom panes updated */
	new_packet_list_select_cb(GTK_TREE_VIEW(packetlist->view), NULL);

	gtk_tree_path_free(path);
}

static gint
row_number_from_iter(GtkTreeIter *iter)
{
	gint row;
	gint *indices;
	GtkTreePath *path;
	GtkTreeModel *model;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	path = gtk_tree_model_get_path(model, iter);
	indices = gtk_tree_path_get_indices(path);
	g_assert(indices);
	/* Indices start from 0, but rows start from 1. Hence +1 */
	row = indices[0] + 1;

	gtk_tree_path_free(path);

	return row;
}

static void
new_packet_list_select_cb(GtkTreeView *tree_view, gpointer data _U_)
{
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	gint row;

	selection = gtk_tree_view_get_selection(tree_view);
	if (!gtk_tree_selection_get_selected(selection, NULL, &iter))
		return;

	row = row_number_from_iter(&iter);

	/* Check if already selected 
	 */
	if (cfile.current_frame && cfile.current_row == row)
		return;

	/* Remove the hex display tab pages */
	while(gtk_notebook_get_nth_page(GTK_NOTEBOOK(byte_nb_ptr), 0))
		gtk_notebook_remove_page(GTK_NOTEBOOK(byte_nb_ptr), 0);

	cf_select_packet(&cfile, row);
	gtk_widget_grab_focus(packetlist->view);

	/* Add newly selected frame to packet history (breadcrumbs) */
	packet_history_add(row);
}

static void
new_packet_list_double_click_cb(GtkTreeView *treeview, GtkTreePath *path _U_,
    GtkTreeViewColumn *col _U_, gpointer userdata _U_)
{
        new_window_cb(GTK_WIDGET(treeview));
}

gboolean
new_packet_list_get_event_row_column(GdkEventButton *event_button,
								 gint *physical_row, gint *row, gint *column)
{
	GtkTreeModel *model = gtk_tree_view_get_model(GTK_TREE_VIEW(packetlist->view));
	GtkTreePath *path;
	GtkTreeViewColumn *view_column;

	if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(packetlist->view),
									  (gint) event_button->x,
									  (gint) event_button->y,
									  &path, &view_column, NULL, NULL)) {
		GtkTreeIter iter;
		GList *cols;
		gint *indices;
		PacketListRecord *record;

		/* Fetch indices */
		gtk_tree_model_get_iter(model, &iter, path);
		indices = gtk_tree_path_get_indices(path);
		g_assert(indices);
		/* Indices start from 0. Hence +1 */
		*row = indices[0] + 1;
		gtk_tree_path_free(path);

		/* Fetch physical row */
		record = new_packet_list_get_record(model, &iter);
		*physical_row = record->fdata->num;

		/* Fetch column */
		/* XXX -doesn't work if columns are re-arranged? */
		cols = gtk_tree_view_get_columns(GTK_TREE_VIEW(packetlist->view));
		*column = g_list_index(cols, (gpointer) view_column);
		g_list_free(cols);

		return TRUE;
	}
	else
		return FALSE;
}

frame_data *
new_packet_list_get_row_data(gint row)
{
	GtkTreePath *path = gtk_tree_path_new();
	GtkTreeIter iter;
	PacketListRecord *record;

	gtk_tree_path_append_index(path, row-1);
	gtk_tree_model_get_iter(GTK_TREE_MODEL(packetlist), &iter, path);

	record = new_packet_list_get_record(GTK_TREE_MODEL(packetlist), &iter);

	gtk_tree_path_free(path);

	return record->fdata;
}

static void
show_cell_data_func(GtkTreeViewColumn *col _U_, GtkCellRenderer *renderer,
			GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
	guint col_num = GPOINTER_TO_INT(data);
	frame_data *fdata;
	const gchar *cell_text;
	PacketListRecord *record;

	record = new_packet_list_get_record(model, iter);
	fdata = record->fdata;

	if (!record->columnized || !record->colorized) {
		packet_list_dissect_and_cache_iter(packetlist, iter,
									  !record->columnized,
									  !record->colorized);
	}

	g_assert(fdata->col_text);

	if (col_based_on_frame_data(&cfile.cinfo, col_num)) {
		col_fill_in_frame_data(fdata, &cfile.cinfo, col_num, FALSE);
		cell_text = cfile.cinfo.col_data[col_num];
	}else
		cell_text = fdata->col_text[col_num];

	g_assert(cell_text);

	if((fdata->color_filter)||(fdata->flags.marked)||(fdata->flags.ignored)){
		gboolean color_on = enable_color;
		GdkColor fg_gdk;
		GdkColor bg_gdk;
		if(fdata->flags.ignored){
			color_t_to_gdkcolor(&fg_gdk, &prefs.gui_ignored_fg);
			color_t_to_gdkcolor(&bg_gdk, &prefs.gui_ignored_bg);
			color_on = TRUE;
		}else if(fdata->flags.marked){
			color_t_to_gdkcolor(&fg_gdk, &prefs.gui_marked_fg);
			color_t_to_gdkcolor(&bg_gdk, &prefs.gui_marked_bg);
			color_on = TRUE;
		}else{
			color_t fg_color_t;
			color_t bg_color_t;
			const color_filter_t *color_filter = fdata->color_filter;

			fg_color_t = color_filter->fg_color;
			bg_color_t = color_filter->bg_color;
			color_t_to_gdkcolor(&fg_gdk, &fg_color_t);
			color_t_to_gdkcolor(&bg_gdk, &bg_color_t);
		}
		g_object_set(renderer,
			 "text", cell_text,
			 "foreground-gdk", &fg_gdk,
			 "foreground-set", color_on,
			 "background-gdk", &bg_gdk,
			 "background-set", color_on,
			 NULL);
	}else{
		g_object_set(renderer,
			 "text", cell_text,
			 "foreground-set", FALSE,
			 "background-set", FALSE,
			 NULL);
	}
}

void
new_packet_list_enable_color(gboolean enable)
{
	enable_color = enable;
	gtk_widget_queue_draw (packetlist->view);
}

void
new_packet_list_queue_draw(void)
{
	gtk_widget_queue_draw (packetlist->view);
}

/* call this after last set_frame_mark is done */
static void mark_frames_ready(void)
{
	file_save_update_dynamics();
	packets_bar_update();
}

static void
set_frame_mark(gboolean set, frame_data *fdata)
{
	if (set)
		cf_mark_frame(&cfile, fdata);
	else
		cf_unmark_frame(&cfile, fdata);
}

static void
set_frame_ignore(gboolean set, frame_data *fdata)
{
	if (set)
		cf_ignore_frame(&cfile, fdata);
	else
		cf_unignore_frame(&cfile, fdata);
}

static void mark_all_frames(gboolean set)
{
	frame_data *fdata;

	/* XXX: we might need a progressbar here */
	for (fdata = cfile.plist_start; fdata != NULL; fdata = fdata->next) {
                if( fdata->flags.passed_dfilter )
		        set_frame_mark(set, fdata);
	}
	mark_frames_ready();
	new_packet_list_queue_draw();
}

void new_packet_list_mark_all_frames_cb(GtkWidget *w _U_, gpointer data _U_)
{
	mark_all_frames(TRUE);
}

void new_packet_list_unmark_all_frames_cb(GtkWidget *w _U_, gpointer data _U_)
{
	mark_all_frames(FALSE);
}

/* Set the selection mode of the packet list window. */
void
new_packet_list_set_sel_browse(gboolean val, gboolean force_set)
{
    GtkSelectionMode new_mode;
    /* initialize with a mode we don't use, so that the mode == new_mode
     * test will fail the first time */
    static GtkSelectionMode mode = GTK_SELECTION_MULTIPLE;

    /* Yeah, GTK uses "browse" in the case where we do not, but oh well. I
     * think "browse" in Wireshark makes more sense than "SINGLE" in GTK+ */
    new_mode = val ? GTK_SELECTION_SINGLE : GTK_SELECTION_BROWSE;

    if ((mode == new_mode) && !force_set) {
        /*
         * The mode isn't changing, so don't do anything.
         * In particular, don't gratuitiously unselect the
         * current packet.
         *
		 * XXX - Copied code from "old" packet list 
		 *  - I don't know if the comment below is still true...
         * XXX - why do we have to unselect the current packet
         * ourselves?  The documentation for the GtkCList at
         *
         *      http://developer.gnome.org/doc/API/gtk/gtkclist.html
         *
         * says "Note that setting the widget's selection mode to
         * one of GTK_SELECTION_BROWSE or GTK_SELECTION_SINGLE will
         * cause all the items in the GtkCList to become deselected."
         */
      return;
    }

    if (cfile.finfo_selected)
        cf_unselect_field(&cfile);

    mode = new_mode;
    gtk_tree_selection_set_mode (gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view)), mode);
}

void
new_packet_list_set_font(PangoFontDescription *font)
{
	gtk_widget_modify_font(packetlist->view, font);
}

void new_packet_list_mark_frame_cb(GtkWidget *w _U_, gpointer data _U_)
{
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	PacketListRecord *record;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	/* model is filled with the current model as a convenience. */
	gtk_tree_selection_get_selected(selection, &model, &iter);
	record = new_packet_list_get_record(model, &iter);

	set_frame_mark(!record->fdata->flags.marked, record->fdata);
	mark_frames_ready();
}

void new_packet_list_ignore_frame_cb(GtkWidget *w _U_, gpointer data _U_)
{
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	PacketListRecord *record;

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
	/* model is filled with the current model as a convenience. */
	gtk_tree_selection_get_selected(selection, &model, &iter);
	record = new_packet_list_get_record(model, &iter);

	set_frame_ignore(!record->fdata->flags.ignored, record->fdata);
	redissect_packets();
}

static void ignore_all_frames(gboolean set)
{
	frame_data *fdata;

	/* XXX: we might need a progressbar here */
	for (fdata = cfile.plist_start; fdata != NULL; fdata = fdata->next) {
                if( fdata->flags.passed_dfilter )
		        set_frame_ignore(set, fdata);
	}
	redissect_packets();
}

void new_packet_list_ignore_all_frames_cb(GtkWidget *w _U_, gpointer data _U_)
{
	ignore_all_frames(TRUE);
}

void new_packet_list_unignore_all_frames_cb(GtkWidget *w _U_, gpointer data _U_)
{
	ignore_all_frames(FALSE);
}


static gboolean
get_col_text_from_record( PacketListRecord *record, gint col_num, gchar** cell_text){

	if (col_based_on_frame_data(&cfile.cinfo, col_num)) {
		col_fill_in_frame_data(record->fdata, &cfile.cinfo, col_num, FALSE);
		*cell_text = g_strdup(cfile.cinfo.col_data[col_num]);
	}else
		*cell_text = g_strdup(record->fdata->col_text[col_num]);

	return TRUE;
}

void
new_packet_list_copy_summary_cb(GtkWidget * w _U_, gpointer data _U_, copy_summary_type copy_type)
{
	gint col;
	gchar *celltext;
	GString* text;
	GtkTreeModel *model;
	GtkTreeSelection *selection;
	GtkTreeIter iter;
	PacketListRecord *record;

	if(CS_CSV == copy_type) {
		text = g_string_new("\"");
	} else {
		text = g_string_new("");
	}

	if (cfile.current_frame) {
		selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(packetlist->view));
		/* model is filled with the current model as a convenience.  */
		gtk_tree_selection_get_selected(selection, &model, &iter);
		record = new_packet_list_get_record(model, &iter);
		for(col = 0; col < cfile.cinfo.num_cols; ++col) {
			if(col != 0) {
				if(CS_CSV == copy_type) {
					g_string_append(text,"\",\"");
				} else {
					g_string_append_c(text, '\t');
				}
			}
			if(get_col_text_from_record( record, col, &celltext)){
				g_string_append(text,celltext);
				g_free(celltext);
			}
		}
		if(CS_CSV == copy_type) {
			g_string_append_c(text,'"');
		}
		copy_to_clipboard(text);
	}
	g_string_free(text,TRUE);
}

void
new_packet_list_recent_write_all(FILE *rf)
{
	gint col, width, num_cols, col_fmt;
	GtkTreeViewColumn *tree_column;
	gchar xalign;

	fprintf (rf, "%s:", RECENT_KEY_COL_WIDTH);
	num_cols = g_list_length(prefs.col_list);
	for (col = 0; col < num_cols; col++) {
		col_fmt = get_column_format(col);
		if (col_fmt == COL_CUSTOM) {
			fprintf (rf, " %%Cus:%s,", get_column_custom_field(col));
		} else {
			fprintf (rf, " %s,", col_format_to_string(col_fmt));
		}
		tree_column = gtk_tree_view_get_column(GTK_TREE_VIEW(GTK_TREE_VIEW(packetlist->view)), col);
		width = gtk_tree_view_column_get_width(tree_column);
		xalign = recent_get_column_xalign (col);
		if (width == 0) {
			/* We have not initialized the packet list yet, use old values */
			width = recent_get_column_width (col);
		}
		fprintf (rf, " %d", width);
		if (xalign != COLUMN_XALIGN_DEFAULT) {
			fprintf (rf, ":%c", xalign);
		}
		if (col != num_cols-1) {
			fprintf (rf, ",");
		}
	}
	fprintf (rf, "\n");
}

GtkWidget *
new_packet_list_get_widget(void)
{
	g_assert(packetlist);
	g_assert(packetlist->view);
	return packetlist->view;
}

void new_packet_list_colorize_packets(void)
{
	packet_list_reset_colorized(packetlist);
	gtk_widget_queue_draw (packetlist->view);
}

#endif /* NEW_PACKET_LIST */

