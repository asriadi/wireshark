#!/bin/bash
#
# $Id$

# 64-bit wrapper for win-setup.sh.

export DOWNLOAD_TAG="2009-11-12"
export WIRESHARK_TARGET_PLATFORM="win64"

WIN_SETUP=`echo $0 | sed -e s/win64/win/`

exec $WIN_SETUP $@
