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

from java.awt import BorderLayout

import json
import os
import re
import traceback

NAME ="Firefox Multi-Container Highlighting"
SHORTNAME = "FMCH"
SETTING_REMOVE_HEADER = "SETTING_REMOVE_HEADER"
SETTING_ENABLED = "SETTING_ENABLED"
SETTING_MAPPINGS = "SETTING_MAPPINGS"


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            print("\n\n*** PYTHON EXCEPTION")
            print(traceback.format_exc(e))
            print("*** END\n")
            raise
    return wrapper


DEBUG = False
def debug(msg):
    if DEBUG:
        print("Debug: {}".format(msg))

class BurpExtender(IBurpExtender, IProxyListener, IContextMenuFactory, IExtensionStateListener):

    remove_header = False

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

        callbacks.registerProxyListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        print("{} loaded".format(NAME))

    def loadConfig(self):
        s_map = self.callbacks.loadExtensionSetting(SETTING_MAPPINGS)
        try:
            if s_map:
                self.colour_mappings = json.loads(s_map)

        except Exception as e:
            print("Error: Unable to load config", e)

        if not self.colour_mappings:
            self.colour_mappings = {
                "sample_container_name_1": "red",
                "sample_container_name_2": "green"
            }

        s_en = self.callbacks.loadExtensionSetting(SETTING_ENABLED)
        self.enabled = False if s_en is None else s_en.lower() == 'true'  # why doesn't bool() work?
        
        s_rh = self.callbacks.loadExtensionSetting(SETTING_REMOVE_HEADER)
        self.remove_header = False if s_rh is None else s_rh.lower() == 'true'  # why doesn't bool() work?
            

    def extensionUnloaded(self):
        debug("Unloading {}".format(NAME))
        self.saveSettings(None)

    @fix_exception
    def processProxyMessage(self, messageIsRequest, message):
        if not self.enabled:
            return
        if not messageIsRequest:
            return
        
        highlight_colour = None
        new_comment = None
        request = self.helpers.analyzeRequest(message.getMessageInfo())
        headers = request.getHeaders()
        for header in headers:
            if header.upper().startswith("X-CONTAINER-ID:"):

                value = header.split(':', 1)[1].strip()

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
                
                if self.remove_header:
                    headers.remove(header)
                
                break

        if highlight_colour:
            message.getMessageInfo().setHighlight(highlight_colour)
            debug("Adding highlight: " + highlight_colour)

        if new_comment:
            comment = message.getMessageInfo().getComment()
            if comment:
                new_comment = "{} - {}".format(comment, new_comment)
            message.getMessageInfo().setComment(new_comment)

        if self.remove_header:
            # debug("Removing header")
            message.getMessageInfo().setRequest(self.helpers.buildHttpMessage(
                headers, 
                message.getMessageInfo().request[request.getBodyOffset():]
            ))
            

    @fix_exception
    def createMenuItems(self, invocation):

        if not invocation.getToolFlag() == self.callbacks.TOOL_PROXY:
            return

        menu = ArrayList()
        subMenu = swing.JMenu("Highlight Firefox Containers")
        self.enable_menu = swing.JCheckBoxMenuItem("Enabled", self.enabled, actionPerformed=self.saveSettings)
        subMenu.add(self.enable_menu)
        self.remove_header_menu = swing.JCheckBoxMenuItem("Remove header", self.remove_header, actionPerformed=self.saveSettings)
        subMenu.add(self.remove_header_menu)

        subMenu.add(swing.JMenuItem("Edit Mappings", actionPerformed=self.editMappings))
        menu.add(subMenu)
        return menu

    @fix_exception
    def editMappings(self, event, text=None):

        if not text:
            text = json.dumps(self.colour_mappings, indent=2)

        msg = swing.JTextArea(text, 10, 80)
        msg.setLineWrap(True)
        msg.setWrapStyleWord(True)
        scroll = swing.JScrollPane(msg)

        resp = swing.JOptionPane.showConfirmDialog(
            None, 
            scroll, 
            "Mappings",
            swing.JOptionPane.OK_CANCEL_OPTION,
            swing.JOptionPane.PLAIN_MESSAGE
        )
        if resp == 0:
            try:
                self.colour_mappings = json.loads(msg.getText())
                self.callbacks.saveExtensionSetting(SETTING_MAPPINGS, json.dumps(self.colour_mappings))
                swing.JOptionPane.showMessageDialog(None, "Mappings saved")
            except Exception as e:
                swing.JOptionPane.showMessageDialog(None, "Unable to parse JSON.\n\n{}".format(e))
                self.editMappings(None, msg.getText())


    @fix_exception
    def saveSettings(self, event):
        debug("Saving settings")
        if event:
            # triggered by right-clicking
            debug("Updating settings")
            self.enabled = self.enable_menu.isSelected()
            self.remove_header = self.remove_header_menu.isSelected()

        self.callbacks.saveExtensionSetting(SETTING_ENABLED, str(self.enabled))
        self.callbacks.saveExtensionSetting(SETTING_REMOVE_HEADER, str(self.remove_header))
        debug("Settings saved")

        