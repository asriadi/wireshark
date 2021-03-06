/* capture_file_dialog.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CAPTURE_FILE_DIALOG_H
#define CAPTURE_FILE_DIALOG_H

#include "display_filter_edit.h"

#include <QFileDialog>

class CaptureFileDialog : public QFileDialog
{
    // The GTK+ Open Capture File dialog has the following elements and features:
    //   - The ability to select a capture file from a list of known extensions
    //   - A display filter entry
    //   - Name resolution checkboxes
    //   - Capture file preview information
    // Ideally we should provide similar functionality here.
    //
    // You can subclass QFileDialog (which we've done here) and add widgets as
    // described at
    // http://developer.qt.nokia.com/faq/answer/how_can_i_add_widgets_to_my_qfiledialog_instance
    // However, Qt's idea of what a file dialog looks like isn't what Microsoft
    // and Apple think a file dialog looks like.
    //
    // On Windows Vista and later we should probably use IFileOpenDialog. On earlier
    // versions of Windows (including XP) we should use GetOpenFileName, which is
    // what we do in ui/win32/file_dlg_win32.c. On OS X we should use NSOpenPanel. On
    // other platforms we should fall back to QFileDialog.
    //
    // Yes, that's four implementations of the same window.
    //
    // If a plain native open file dialog is good enough we can just the static
    // version of QFileDialog::getOpenFileName. (Commenting out Q_OBJECT and
    // "explicit" below has the same effect.)

    Q_OBJECT
public:
    explicit CaptureFileDialog(QWidget *parent, QString &fileName, QString &displayFilter);

private:
#if !defined(Q_WS_WIN)
    void append_file_type(QStringList &filters, int ft);
    QStringList build_file_open_type_list(void);
#endif // Q_WS_WIN

    QString &m_fileName;
    QString &m_displayFilter;
    QCheckBox m_macRes;
    QCheckBox m_transportRes;
    QCheckBox m_networkRes;
    QCheckBox m_externalRes;

    QLabel m_previewFormat;
    QLabel m_previewSize;
    QLabel m_previewPackets;
    QLabel m_previewFirst;
    QLabel m_previewElapsed;
    QList<QLabel *> m_previewLabels;

    DisplayFilterEdit* m_displayFilterEdit;

signals:

public slots:

    int exec();

private slots:
#if !defined(Q_WS_WIN)
    void preview(const QString & path);
#endif // Q_WS_WIN
};

#endif // CAPTURE_FILE_DIALOG_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
