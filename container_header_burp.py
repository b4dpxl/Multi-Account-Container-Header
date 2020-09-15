__author__ = "b4dpxl"
__license__ = "MIT"
__version__ = "1.0"

"""
Totally based on https://github.com/PortSwigger/multi-browser-highlighting
"""

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IInterceptedProxyMessage
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from java.awt import Desktop
from javax import swing

from java.io import File
from java.util import List, ArrayList

import json
import os
import re

NAME ="Firefox Multi-Container Highlighting"
SHORTNAME = "FMCH"

def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            print("\n\n*** PYTHON EXCEPTION")
            print(e)
            print("*** END\n")
            raise
    return wrapper


DEBUG = False
def debug(msg):
    if DEBUG:
        print("Debug: {}".format(msg))

class BurpExtender(IBurpExtender, IProxyListener, IContextMenuFactory, IExtensionStateListener):

    folder = os.path.expanduser("~/.FMCH")
    file = os.path.join(folder, "config.json")

    def registerExtenderCallbacks( self, callbacks):

        sys.stdout = callbacks.getStdout()  
        sys.stderr = callbacks.getStderr()

        # Keep a reference to our callbacks and helper object
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        self.valid_colours =["red", "blue", "pink", "green", "magenta", "cyan", "orange", "gray", "yellow"]

        self.colour_mappings = {}
        self.loadConfig()
        # Colors for different browsers

        self.callbacks.setExtensionName(NAME)
        self.enabled = True

        callbacks.registerProxyListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        print("{} loaded".format(NAME))

    def loadConfig(self):
        try:
            if not os.path.exists(self.folder):
                os.mkdir(self.folder)

            if not os.path.exists(self.file):
                with open(self.file, 'w') as f:

                    sample = {
                        "valid_colours": self.valid_colours,
                        "mappings": {
                            "sample_container_name_1": "red",
                            "sample_container_name_2": "green"
                        }
                    }

                    print("Creating sample config file")
                    f.write(json.dumps(sample, indent=4))

            with open(self.file, 'r') as f:
                config = json.load(f)
                self.colour_mappings = config.get("mappings")
                debug("Mappings: " + json.dumps(self.colour_mappings, indent=4))

        except Exception as e:
            print("Error: Unable to load config", e)

    def extensionUnloaded(self):
        debug("Unloading {}".format(NAME))

    def processProxyMessage(self, messageIsRequest, message):
        if not self.enabled:
            return
        if not messageIsRequest:
            return
        
        highlight_colour = None
        new_comment = None
        headers = self.helpers.analyzeRequest(message.getMessageInfo()).getHeaders()[1:]

        for name, value in [(x.strip(), y.strip()) for x,y in [x.split(":", 1) for x in headers[1:] if ":" in x]]:
            if name == "X-CONTAINER-ID":

                if value in self.colour_mappings:
                    col = self.colour_mappings.get(value, '').lower()
                    if col in self.valid_colours:
                        debug("Mapping {} to colour {}".format(value, col))
                        highlight_colour = col

                elif value.lower() in self.valid_colours:
                    debug("Using colour {}".format(value.lower()))
                    highlight_colour = value.lower()

                else:
                    debug("Unmapped container ID: {}".format(value))

                new_comment = "Container: {}".format(value)

        if highlight_colour:
            message.getMessageInfo().setHighlight(highlight_colour)
        if new_comment:
            comment = message.getMessageInfo().getComment()
            if comment:
                new_comment = "{} - {}".format(comment, new_comment)
            message.getMessageInfo().setComment(new_comment)

    @fix_exception
    def createMenuItems(self, invocation):

        if not invocation.getToolFlag() == self.callbacks.TOOL_PROXY:
            return

        menu = ArrayList()
        subMenu = swing.JMenu("Highlight Firefox Containers")
        subMenu.add(swing.JMenuItem("Disable" if self.enabled else "Enable", actionPerformed=self.toggle))
        subMenu.add(swing.JMenuItem("Edit Config", actionPerformed=self.editConfig))
        subMenu.add(swing.JMenuItem("Reload Config", actionPerformed=self.reloadConfig))
        menu.add(subMenu)
        return menu

    def reloadConfig(self, event):
        self.loadConfig()

    def editConfig(self, event):
        try:
            Desktop.getDesktop().open(File(self.file))
        except Exception as e:
            print("Error: Unable to launch desktop API", e)

    def toggle(self, event):
        self.enabled = not self.enabled
        