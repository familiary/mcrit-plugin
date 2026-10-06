#!/usr/bin/python
########################################################################
# Copyright (c) 2012
# Daniel Plohmann <daniel.plohmann<at>gmail<dot>com>
# Alexander Hanel <alexander.hanel<at>gmail<dot>com>
# All rights reserved.
########################################################################
#
#  This file is part of IDAscope
#
#  IDAscope is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

import mcrit_plugin.ui_qt.QtShim as QtShim

QTableWidgetItem = QtShim.get_QTableWidgetItem()


class NumberQTableWidgetItem(QTableWidgetItem):
    """
    A simple helper class that allows sorting by numeric values.
    """

    def __lt__(self, other):
        """
        Redefine function from QTableWidgetItem to allow sorting by numeric value instead of string value.
        @param other: another item of the same type
        @type other: I{NumberQTableWidgetItem}
        @return: (boolean) the numeric comparison of the items.
        """
        # an exception raised here escapes into Qt's sort, which crashes PySide6 6.11
        return _sort_key(self.text()) < _sort_key(other.text())


def _sort_key(text):
    """Numbers by value, then text; one key keeps the order consistent for mixed columns."""
    try:
        return (0, _numeric(text), "")
    except ValueError:
        return (1, 0, text)


def _numeric(text):
    return int(text, 16) if text.startswith("0x") else float(text)
