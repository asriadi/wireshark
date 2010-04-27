/* value_string.h
 * Definitions for value_string structures and routines
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __VALUE_STRING_H__
#define __VALUE_STRING_H__

#include <glib.h>

/* Struct for the val_to_str, match_strval_idx, and match_strval functions */

typedef struct _value_string {
  guint32  value;
  const gchar   *strptr;
} value_string;

struct _value_string_ext;
typedef const char *(*value_string_match_t)(const guint32, const struct _value_string_ext *);

typedef struct _value_string_ext {
  value_string_match_t match;
  guint length;                 /* length of the array */
  const value_string *vals;     /* the value string */
} value_string_ext;

const gchar *match_strval_ext_init(const guint32 val, value_string_ext *vse);
#define VALUE_STRING_EXT_INIT(x) { (value_string_match_t) match_strval_ext_init, array_length(x)-1, x }

/* Struct for the str_to_str, match_strstr_idx, and match_strstr functions */

typedef struct _string_string {
  const gchar   *value;
  const gchar   *strptr;
} string_string;

/* Struct for the rval_to_str, match_strrval_idx, and match_strrval functions */
typedef struct _range_string {
  guint32        value_min;
  guint32        value_max;
  const gchar   *strptr;
} range_string;

/* #define VS_DEF(x) { x, #x } */
/* #define VS_END    { 0, NULL } */

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
extern const gchar* match_strval_idx(const guint32 val, const value_string *vs, gint *idx);

/* Like match_strval_idx(), but doesn't return the index. */
extern const gchar* match_strval(const guint32 val, const value_string *vs);
extern const gchar* match_strval_ext(const guint32 val, const value_string_ext *vs);

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
extern const gchar* val_to_str(const guint32 val, const value_string *vs, const char *fmt);
extern const gchar* val_to_str_ext(const guint32 val, const value_string_ext *vs, const char *fmt);

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Returns 'unknown_str', on failure. */
extern const gchar* val_to_str_const(const guint32 val, const value_string *vs, const char *unknown_str);
extern const gchar* val_to_str_ext_const(const guint32 val, const value_string_ext *vs, const char *unknown_str);

/* Tries to match val against each element in the string_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
extern const gchar* match_strstr_idx(const gchar *val, const string_string *vs, gint *idx);

/* Like match_strval_idx(), but doesn't return the index. */
extern const gchar* match_strstr(const gchar *val, const string_string *vs);

/* Tries to match val against each element in the string_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
extern const gchar* str_to_str(const gchar *val, const string_string *vs, const char *fmt);

/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
extern const char *decode_enumerated_bitfield(const guint32 val, const guint32 mask,
  const int width, const value_string *tab, const char *fmt);

/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
extern const char *decode_enumerated_bitfield_shifted(const guint32 val, const guint32 mask,
  const int width, const value_string *tab, const char *fmt);


/* ranges aware versions */

/* Tries to match val against each range in the range_string array rs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
extern const gchar* rval_to_str(const guint32 val, const range_string *rs, const char *fmt);

/* Tries to match val against each range in the range_string array rs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
extern const gchar *match_strrval_idx(const guint32 val, const range_string *rs, gint *idx);

/* Like match_strrval_idx(), but doesn't return the index. */
extern const gchar *match_strrval(const guint32 val, const range_string *rs);

#endif /* __VALUE_STRING_H__ */
