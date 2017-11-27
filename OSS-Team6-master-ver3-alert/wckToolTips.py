#
# WCKLIB
# $Id$
#
# tooltips for arbitrary Tkinter widgets
#
# written by Fredrik Lundh, June 1997.  changed to use a global controller
# in September 2007.
#
# Copyright (c) 1997-2007 by Fredrik Lundh.  All rights reserved.
#
# --------------------------------------------------------------------
# License
# 
# The Tkinter 3000 Widget Construction Kit is
# 
# Copyright (c) 1998-2007 by Secret Labs AB
# Copyright (c) 1998-2007 by Fredrik Lundh
# 
# By obtaining, using, and/or copying this software and/or its
# associated documentation, you agree that you have read, understood,
# and will comply with the following terms and conditions:
# 
# Permission to use, copy, modify, and distribute this software and its
# associated documentation for any purpose and without fee is hereby
# granted, provided that the above copyright notice appears in all
# copies, and that both that copyright notice and this permission notice
# appear in supporting documentation, and that the name of Secret Labs
# AB or the author not be used in advertising or publicity pertaining to
# distribution of the software without specific, written prior
# permission.
# 
# SECRET LABS AB AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS.  IN NO EVENT SHALL SECRET LABS AB OR THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# 
# --------------------------------------------------------------------
#

import tkinter as tk

class ToolTipManager:

    label = None
    window = None
    active = 0

    def __init__(self):
        self.tag = None

    def getcontroller(self, widget):
        if self.tag is None:

            self.tag = "ui_tooltip_%d" % id(self)
            widget.bind_class(self.tag, "<Enter>", self.enter)
            widget.bind_class(self.tag, "<Leave>", self.leave)

            # pick suitable colors for tooltips
            try:
                self.bg = "systeminfobackground"
                self.fg = "systeminfotext"
                widget.winfo_rgb(self.fg) # make sure system colors exist
                widget.winfo_rgb(self.bg)
            except:
                self.bg = "#ffffe0"
                self.fg = "black"

        return self.tag

    def register(self, widget, text):
        widget.ui_tooltip_text = text
        tags = list(widget.bindtags())
        tags.append(self.getcontroller(widget))
        widget.bindtags(tuple(tags))

    def unregister(self, widget):
        tags = list(widget.bindtags())
        tags.remove(self.getcontroller(widget))
        widget.bindtags(tuple(tags))

    # event handlers

    def enter(self, event):
        widget = event.widget
        if not self.label:
            # create and hide balloon help window
            self.popup = tk.Toplevel(bg=self.fg, bd=1)
            self.popup.overrideredirect(1)
            self.popup.withdraw()
            self.label = tk.Label(
                self.popup, fg=self.fg, bg=self.bg, bd=0, padx=2
                )
            self.label.pack()
            self.active = 0
        self.xy = event.x_root + 16, event.y_root + 10
        self.event_xy = event.x, event.y
        self.after_id = widget.after(200, self.display, widget)

    def display(self, widget):
        if not self.active:
            # display balloon help window
            text = widget.ui_tooltip_text
            if callable(text):
                text = text(widget, self.event_xy)
            self.label.config(text=text)
            self.popup.deiconify()
            self.popup.lift()
            self.popup.geometry("+%d+%d" % self.xy)
            self.active = 1
            self.after_id = None

    def leave(self, event):
        widget = event.widget
        if self.active:
            self.popup.withdraw()
            self.active = 0
        if self.after_id:
            widget.after_cancel(self.after_id)
            self.after_id = None

_manager = ToolTipManager()

##
# Registers a tooltip for a given widget.
#
# @param widget The widget object.
# @param text The tooltip text.  This can be either a string, or a callable
#     object. If callable, it is called as text(widget) when the tooltip is
#     about to be displayed, and the returned text is displayed instead.

def register(widget, text):
    _manager.register(widget, text)

##
# Unregisters a tooltip.  Note that the tooltip information is automatically
# destroyed when the widget is destroyed.

def unregister(widget):
    _manager.unregister(widget)

if __name__ == "__main__":

    root = Tk()

    root.title("ToolTips")

    b1 = Button(root, bg="red", text="red")
    b1.pack()

    register(b1, "A red button")

    b2 = Button(root, bg="green", text="green")
    b2.pack()

    register(b2, "A green button")

    b3 = Button(root, fg="blue", text="blue")
    b3.pack()

    def cb(*args):
        return "A blue text"

    register(b3, cb)
    # unregister(b3)

    mainloop()
