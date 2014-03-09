#!/usr/bin/env python2
"""
hexasm
Copyright (C) 2014  Jan Kasiak

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""
import curses
import re
import sys

import udis86

hex_re = re.compile("^\\$0x[0-9|a-f]+$")
reg_re = re.compile("^\\%[0-9|a-z]+$")
invalid_re = re.compile("^invalid$")
prefixes = set(["26", "2E", "36", "3E", "64", "65", "66", "67", "F0", "F2",
                "F3"])

def group(l, n):
    return zip(*[l[i::n] for i in range(n)])


class HexAsmView(object):
    """docstring for HexAsmView"""
    def __init__(self, stdscr, buffer, width, height, px, py):
        super(HexAsmView, self).__init__()
        self.stdscr = stdscr
        self.buffer = buffer or []
        self.width = width
        self.height = height
        self.px = px
        self.py = py

        self.cx, self.cy, self.x, self.y = 0, 0, 0, 0
        self.pad = None
        self.mode = 'i'
        self.history = []
        self.history_index = -1

        self.prefix_window = curses.newwin(3, 13, self.py, self.px + 10)
        self.rex_window = curses.newwin(3, 4, self.py, self.px + 30)
        self.rex_bits_window = curses.newwin(3, 9, self.py, self.px + 35)
        self.modrm_window = curses.newwin(3, 4, self.py, self.px + 54)
        self.modrm_bits_window = curses.newwin(3, 12, self.py,
                                               self.px + 59)
        self.sib_window = curses.newwin(3, 4, self.py, self.px + 78)
        self.sib_bits_window = curses.newwin(3, 12, self.py,
                                             self.px + 83)

        self.top_bar_height = 4

        self.disassemble()
        self.refresh()

    def disassemble(self):
        """Disassemble the buffer and update pad

        """
        self.u = udis86.init()
        self.u.set_input_buffer(self.buffer)
        self.u.set_mode(udis86.MOD_64)
        self.u.set_pc(0)
        self.u.set_syntax(udis86.UD_VENDOR_INTEL)
        self.off = []
        self.data = []
        self.ins = []
        self.modrm = []
        self.primary_opcode = []
        while self.u.disassemble():
            self.off.append("%08x" % self.u.insn_off())
            self.data.append(self.u.insn_hex())
            self.ins.append(self.u.insn_asm())
            self.modrm.append((self.u.have_modrm, self.u.modrm))
            self.primary_opcode.append(self.u.primary_opcode)

        # Redo pad on line count change
        if self.pad is not None and self.pad.getmaxyx()[0] != len(self.data) + 2:
            self.pad.clear()
            self.stdscr.clear()
            self.stdscr.refresh()
            self.redraw_base()
            self.pad = None
        elif self.pad is not None:  # Erase and draw redraw borders
            self.pad.erase()
            self.pad.border()
            self.redraw_base()

        if self.pad is None:  # First time
            self.pad = curses.newpad(len(self.data) + 2, self.width)
            self.pad.border()
            self.redraw_base()

        # Fill pad buffer
        y = 1
        for i, (off, data, asm) in enumerate(zip(self.off, self.data, self.ins)):
            x = 1
            # Write offset
            for h in off:
                self.pad.addch(y, x, h, curses.color_pair(1))
                x += 1
            x += 2
            # Write hex
            can_prefix = True
            can_rex = False
            can_op = False
            can_mod = False
            can_sib = False
            can_other = False
            for h in group(data, 2):
                hit = False
                h = "".join(h)
                color = 0
                if can_prefix:
                    if h in prefixes:
                        color = curses.color_pair(6)
                    else:
                        can_prefix = False
                        can_rex = True
                if can_rex:
                    if h[0] == "4":
                        color = curses.color_pair(6)
                        hit = True
                    can_rex = False
                    can_op = True
                if can_op and not hit:
                    # if int("0x%s" % h, base=16) == self.primary_opcode[self.y]:
                    color = curses.color_pair(2)
                    hit = True
                    can_op = False
                    can_mod = True
                if can_mod and not hit:
                    if self.modrm[i][0]:
                        color = curses.color_pair(4)
                        hit = True
                    can_mod = False
                    can_sib = True
                if can_sib and not hit:
                    if self.modrm[i][0]:
                        m = hex(self.modrm[i][1])[2:]
                        m = "0" * (2 - len(m)) + m
                        b = bin(int("0x%s" % m, base=16))[2:]
                        b = "0" * (8 - len(b)) + b
                        if b[0:2] == "11" or b[5:] != "100":
                            color = curses.color_pair(4)
                            hit = True
                    can_sib = False
                    can_other = True
                if can_other and not hit:
                    color = curses.color_pair(3)
                if asm.rstrip().lstrip() == "invalid":
                    color = curses.color_pair(5)
                self.pad.addstr(y, x, h, color)
                x += 3
            # Write instructions
            x = 42
            x += 5
            p = asm.split()
            # Write out rest
            for i in p:
                color = None
                stripped = i.lstrip(',').rstrip(',').strip().rstrip()
                if re.match("^[\w]+$", stripped):
                    color = curses.color_pair(2)
                if stripped == "invalid":
                    color = curses.color_pair(5)
                # Highlight hex color
                if hex_re.match(stripped):  # Strip comma
                    color = curses.color_pair(3)
                # Highlight reg
                if reg_re.match(stripped):  # Strip comma
                    color = curses.color_pair(4)
                if i[-1] == ',':
                    self.pad.addstr(y, x, i[0:-1], color or 0)
                    self.pad.addstr(y, x + len(i) - 1, i[-1], 0)
                else:
                    self.pad.addstr(y, x, i, color or 0)
                x += len(i) + 1
            y += 1

    def redraw_base(self):
        self.stdscr.addstr(self.py + 1, self.px, "Prefixes:", curses.color_pair(7))
        self.stdscr.addstr(self.py + 1, self.px + 25, "REX:", curses.color_pair(7))
        self.stdscr.addstr(self.py + 1, self.px + 46, "ModR/M:", curses.color_pair(7))
        self.stdscr.addstr(self.py + 1, self.px + 73, "SIB:", curses.color_pair(7))
        self.stdscr.addstr(self.py + 3, self.px + 11, "P1 P2 P3 P4")
        self.stdscr.addstr(self.py + 3, self.px + 35, " W R X B")
        self.stdscr.addstr(self.py + 3, self.px + 58, " MOD REG  RM")
        self.stdscr.addstr(self.py + 3, self.px + 82, "  SC IDX  BS")
        self.stdscr.refresh()
        self.prefix_window.border()
        self.rex_window.border()
        self.rex_bits_window.border()
        self.modrm_window.border()
        self.modrm_bits_window.border()
        self.sib_window.border()
        self.sib_bits_window.border()

    def update_special_bytes(self):
        # Do prefix parsing
        p = ["00", "00", "00", "00"]
        index = 0
        for i, h in enumerate(group(self.data[self.y], 2)):
            h = "".join(h)
            if h in prefixes:
                p[i] = h
                index += 1
            else:
                break
        for i, pp in enumerate(p):
            self.prefix_window.addstr(1, 1 + i * 3, pp, curses.color_pair(6) if pp != "00" else 0)
            # self.prefix_window.addstr(1, 1, "%s %s %s %s" % (p[0], p[1], p[2], p[3]))
        # Rex parsing
        r = self.data[self.y][index*2:(index*2)+2]
        if len(r) == 0:
            r = "00"
        if r[0] == "4":
            index += 1
        else:
            r = "00"
        self.rex_window.addstr(1, 1, r, curses.color_pair(6) if r != "00" else 0)
        b = bin(int("0x%s" % r, base=16))[2:] if r != "00" else "0" * 8
        self.rex_bits_window.addstr(1, 1, "%s %s %s %s" % (b[-4], b[-3], b[-2],
                                                           b[-1]), curses.color_pair(6) if r != "00" else 0)
        # Skip opcode - not accurate
        index += 1

        # ModRM
        m = hex(self.modrm[self.y][1])[2:]
        m = "0" * (2 - len(m)) + m
        if not self.modrm[self.y][0]:
            m = "00"
        index += 1
        self.modrm_window.addstr(1, 1, m, curses.color_pair(4) if self.modrm[self.y][0] else 0)
        b = bin(int("0x%s" % m, base=16))[2:]
        b = "0" * (8 - len(b)) + b
        self.modrm_bits_window.addstr(1, 1, "%s%s %s%s%s %s%s%s" % (
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]), curses.color_pair(4) if self.modrm[self.y][0] else 0)

        # SIB
        # TODO: fix actual offset
        s = self.data[self.y][index*2:(index*2)+2]
        has_sib = True
        if len(s) == 0 or b[0:2] == "11" or b[5:] != "100":
            s = "00"
            has_sib = False

        self.sib_window.addstr(1, 1, s, curses.color_pair(7) if has_sib else 0)
        b = bin(int("0x%s" % s, base=16))[2:]
        b = "0" * (8 - len(b)) + b
        self.sib_bits_window.addstr(1, 1, "%s%s %s%s%s %s%s%s" % (
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]))

    def move_x_line(self, x):
        """Move to the start or end of the current line

        Arguments:
        x - start/end 0/1

        """
        if x == 0:
            self.x = 0
        else:
            self.x = len(self.data[self.y]) - 1

    def move_x(self, x):
        """Move cursor in the x position. Line wraps

        Arguments:
        x - number of positions to move

        """
        if self.x + x < 0:
            if self.y - 1 >= 0:
                self.move_y(-1)
                self.x = len(self.data[self.y]) - 1
            else:
                self.x = 0
        elif self.x + x >= len(self.data[self.y]):
            if self.y < len(self.data) - 1:
                self.move_y(1)
                self.x = 0
        else:
            self.x += x

    def move_page(self, y):
        if y == 1:
            self.move_y(10)
        elif y == -1:
            self.move_y(-10)

    def move_y(self, y):
        """Move cursor in the y position.

        Arguments:
        y - number of lines to move

        """
        if self.y + y < 0:
            self.y = 0
        elif self.y + y >= len(self.data):
            self.y = len(self.data) - 1
            if len(self.data) + 2 >= self.height:
                self.cy = self.y - self.height + 2
        else:
            self.y += y
        # Update viewport scroll
        if self.y > self.cy + self.height - 1:
            self.cy = self.y - self.height + 1
        elif self.y <= self.cy - 1:
            self.cy = self.y

        # If line is longer, move back x
        if self.x >= len(self.data[self.y]):
            self.x = len(self.data[self.y]) - 1

    def set_4bit(self, c):
        """Update 4 bits of a value where the cursor is currently located

        Arguments:
        c - hex string [0-F]

        """
        h = int("0x%s" % c, base=16)
        # Sum up string lines to get offset into folded buffer
        i = (sum([len(x) for x in self.data[0:self.y]]) +
             (self.x - 1 if self.x % 2 == 1 else self.x)) / 2
        # Update upper half
        if self.x % 2 == 0:
            v = chr((ord(self.buffer[i]) & 0x0F) | (h << 4))
        else:  # Update lower half
            v = chr((ord(self.buffer[i]) & 0xF0) | (h))
        # Nothing to change
        if v != self.buffer[i]:
            # Record change in history
            self.log(i, self.buffer[i], v)
            # Update buffer
            self.buffer = self.buffer[0:i] + v + self.buffer[i + 1:]
            # Disassemble again
            self.disassemble()
        # If we're in insert mode, move forward
        if self.mode == 'i':
            self.move_x(1)

    def insert(self):
        """Insert a 0xFF at the current cursor position

        """
        # Sum up string lines to get offset into folded buffer
        i = (sum([len(x) for x in self.data[0:self.y]]) +
             (self.x - 1 if self.x % 2 == 1 else self.x)) / 2
        if self.x % 2 != 0:
            i += 1
        # Record change in history
        self.log(i, "",  '\xFF')
        # Update buffer
        self.buffer = self.buffer[0:i] + '\xFF' + self.buffer[i:]
        # Disassemble again
        self.disassemble()
        self.check_cursor()

    def delete(self):
        """Delete the current byte

        """
        # Don't allow deletion of the last byte
        if len(self.data) == 1 and len(self.data[0]) == 2:
            return
        # Sum up string lines to get offset into folded buffer
        i = (sum([len(x) for x in self.data[0:self.y]]) +
             (self.x - 1 if self.x % 2 == 1 else self.x)) / 2
        # Record change in history
        self.log(i, self.buffer[i], "")
        # Update buffer
        self.buffer = self.buffer[0:i] + self.buffer[i + 1:]
        # Disassemble again
        self.disassemble()
        self.check_cursor()

    def check_cursor(self):
        # If lines change
        if self.y >= len(self.data):
            self.move_y(-1)
        if self.x >= len(self.data[self.y]):
            self.move_x(-2)

    def log(self, i, o, n):
        """Log a history change

        Arguments:
        i - buffer index
        o - old value
        n - new value

        """
        self.history_index += 1
        self.history = self.history[0:self.history_index]
        self.history.append((i, o, n))

    def undo(self):
        """Undo an edit

        """
        if self.history_index >= 0:
            i, o, n = self.history[self.history_index]
            self.history_index -= 1
            if n != "":
                self.buffer = self.buffer[0:i] + o + self.buffer[i + 1:]
            else:
                self.buffer = self.buffer[0:i] + o + self.buffer[i:]
            self.disassemble()
            self.check_cursor()

    def redo(self):
        """Redo an edit

        """
        if self.history_index < len(self.history) - 1:
            i, o, n = self.history[self.history_index + 1]
            self.history_index += 1
            if o != "":
                self.buffer = self.buffer[0:i] + n + self.buffer[i + 1:]
            else:
                self.buffer = self.buffer[0:i] + '\xFF' + self.buffer[i:]
            self.disassemble()
            self.check_cursor()

    def refresh(self):
        """Refresh the pad and cursor position

        """
        self.update_special_bytes()
        self.prefix_window.refresh()
        self.rex_window.refresh()
        self.rex_bits_window.refresh()
        self.modrm_window.refresh()
        self.modrm_bits_window.refresh()
        self.sib_window.refresh()
        self.sib_bits_window.refresh()

        self.pad.refresh(self.cy, 0, self.py + self.top_bar_height,
                         self.px, self.height, self.width)
        self.stdscr.move(self.y + 1 - self.cy + self.py + self.top_bar_height,
                         self.x + 10 + 1 + self.px + self.x / 2)


def main(stdscr):
    # Curses init
    stdscr.clear()
    stdscr.refresh()
    curses.start_color()
    curses.curs_set(1)

    curses.init_pair(1, 8, curses.COLOR_BLACK)
    curses.init_pair(2, 28, curses.COLOR_BLACK)
    curses.init_pair(3, 26, curses.COLOR_BLACK)
    curses.init_pair(4, 93, curses.COLOR_BLACK)
    curses.init_pair(5, 160, curses.COLOR_BLACK)
    curses.init_pair(6, 166, curses.COLOR_BLACK)
    curses.init_pair(7, 124, curses.COLOR_BLACK)
    # curses.init_pair(8, )

    d = open(sys.argv[1], "r").read()
    v = HexAsmView(stdscr, d, 100, stdscr.getmaxyx()[0], 0, 0)

    while 1:
        c = stdscr.getch()
        if c == ord('q'):
            break
        elif c == ord('o'):
            v.mode = 'o'
        elif c == ord('i'):
            v.mode = 'i'
        elif c == ord('u'):
            v.undo()
        elif c == ord('r'):
            v.redo()
        elif c == ord('t'):
            v.delete()
        elif c == ord('y'):
            v.insert()
        elif c == curses.KEY_LEFT:
            v.move_x(-1)
        elif c == curses.KEY_RIGHT:
            v.move_x(1)
        elif c == curses.KEY_DOWN:
            v.move_y(1)
        elif c == curses.KEY_UP:
            v.move_y(-1)
        elif c == curses.KEY_NPAGE:
            v.move_page(1)
        elif c == curses.KEY_PPAGE:
            v.move_page(-1)
        elif c == curses.KEY_HOME:
            v.move_x_line(0)
        elif c == curses.KEY_END:
            v.move_x_line(1)
        elif ord('0') <= c <= ord('9') or ord('a') <= c <= ord('f'):
            v.set_4bit(chr(c))
        v.refresh()
        stdscr.refresh()


curses.wrapper(main)
