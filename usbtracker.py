import argparse
import sys
import os.path
import _winreg
import mmap
import contextlib

from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
from Evtx.Views import evtx_template_readable_view
from utilities import utils
from evt.event import Event
from evt.eventxml import EventXML

import xml.etree.ElementTree as ET


def main():

    usage()
    parser = argparse.ArgumentParser()
    group_reg = parser.add_mutually_exclusive_group()
    group_reg.add_argument("-u", "--usbstor", help="Dump USB artifacts from USBSTOR registry", action="store_true")
    group_reg.add_argument("-uu", "--usbstor-verbose", help="Dump USB detailed artifacts from USBSTOR registry.",
                           action="store_true")
    parser.add_argument("-nh", "--no-hardwareid", help="Hide HardwareID value during a USBSTOR detailed artifacts "
                                                       "registry dump.", action="store_true")

    group_log = parser.add_mutually_exclusive_group()
    group_log.add_argument("-df", "--driver-frameworks", help="Dump USB artifacts and events from the Windows "
                                                              "DriverFrameworks Usermode log.", action="store_true")
    group_log.add_argument("-x", "--raw-xml-event", help="Display event results in raw xml (with -df option only).",
                        action="store_true")

    parser.add_argument("-sa", "--setupapi-dev", help="Dump all USB devices installation (first use) artifacts from the"
                                                      " setupapi.dev.log file. (Vista and later)", action="store_true")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.usbstor:
        dump_registry()
    elif args.usbstor_verbose:
        if args.no_hardwareid:
            dump_extra_registry(True)
        else:
            dump_extra_registry(False)

    if args.driver_frameworks:
        dump_driverframeworks_log(
            r'C:\Windows\SysNative\winevt\Logs\Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx',
            args.raw_xml_event)

    if args.setupapi_dev:
        dump_setupapi_log(r'C:\Windows\inf\setupapi.dev.log')


def usage():

    print("USBTracker alpha")
    print("2015 - Alain Sullam\n")
    print("USBTracker it's a free tool which allow you to extract some USB artifacts from a Windows OS (Vista and "
          "later).")
    print("You must execute USBTracker inside a CMD/Powershell console runnnig with administror privileges to be able "
          "to dump some log files artifacts.\n ")


def dump_registry():

    print("USB device(s) know by this computer :")
    print("=====================================\n")
    query = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Enum\USBSTOR', 0)
    i = 0
    try:
        while True:
            print _winreg.EnumKey(query, i)
            i += 1

    except WindowsError:
        print("\n\n")
        pass


def dump_extra_registry(hide_hardwareid):

    print("USB device(s) know by this computer :")
    print("=====================================\n")

    query = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Enum\USBSTOR', 0)
    i = 0

    try:
        while True:
            key = _winreg.EnumKey(query, i)
            print key + "\n"
            i += 1
            query2 = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Enum\USBSTOR' + "\\" +
                                     key, 0)
            j = 0

            try:
                while True:
                    subkey = _winreg.EnumKey(query2, j)
                    print("        " + "Serial : " + subkey + "\n")
                    j += 1
                    query3 = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Enum\USBSTOR' +
                                             "\\" + key + "\\" + subkey, 0)
                    k = 0
                    try:
                        while True:
                            value_tuple = _winreg.EnumValue(query3, k)
                            if hide_hardwareid is True:
                                if value_tuple[0] != "HardwareID":
                                    print("        " + value_tuple[0] + " : " + str(value_tuple[1]))
                            else:
                                print("        " + value_tuple[0] + " : " + str(value_tuple[1]))
                            k += 1
                    except WindowsError, ex:
                        pass

            except WindowsError, ex:
                pass

            print("\n======================================================================\n")

    except WindowsError, ex:
        pass


def dump_driverframeworks_log(event_file, xml_format):

    events_list = list()

    if os.path.isfile(event_file) is False:
        print("The log file : " + event_file + " is not found.")
        return

    print("USB related event(s) found in the event log :")
    print("=============================================\n")

    with open(event_file, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)

            for xml, record in evtx_file_xml_view(fh):
                root = ET.fromstring(xml)

                if root[0][1].text == '2003' or root[0][1].text == '2004' or root[0][1].text == '2005' or \
                        root[0][1].text == '2010' or root[0][1].text == '2100' or root[0][1].text == '2102' or \
                        root[0][1].text == '2105':

                    if xml_format:
                        evt = EventXML(root[0][7].get('SystemTime'), xml)
                        events_list.append(evt)
                    else:
                        evt = Event(root[0][7].get('SystemTime'),
                                    root[0][1].text, root[0][12].text,
                                    root[0][13].get('UserID'),
                                    utils.find_username_by_sid(root[0][13].get('UserID')),
                                    str.split(str(root[1][0].tag), "}")[1],
                                    str(root[1][0].get('lifetime')),
                                    str(root[1][0].get('instance')))
                        events_list.append(evt)

            events_list.sort(key=lambda x: x.datetime)

            if xml_format:
                for eventxml in events_list:
                    print eventxml.xmlstring

            else:
                for event in events_list:
                    print "UTC Time : " + event.datetime
                    print "EventID : " + event.event_id + " | Description : " + event.description + \
                          " | Computer : " + event.computer_name + " | User SID : " + event.user_sid + \
                          " | User : " + event.user
                    print "Lifetime : " + event.lifetime
                    print event.device_instance_id + "\n"

            print str(len(events_list)) + " event(s) found."


def dump_setupapi_log(event_file):

    if os.path.isfile(event_file) is False:
        print("The log file : " + event_file + " is not found.")
        return

    events_list = list()

    toggle = False

    with open(event_file, "rb") as fp:
        lines = []
        for line in fp:
            if ">>>  [" in line and "Device" in line and ("usb" in line or "USB" in line or "Usb" in line):
                lines.append(line[:-1]) if line[-1] == "\n" else lines.append(line)
                toggle = True
            elif ">>>  Section start" in line and toggle is True:
                lines.append(line[:-1] + "\n") if line[-1] == "\n" else lines.append(line + "\n")
                toggle = False

    for line2 in lines:
        print line2



if __name__ == "__main__":
    main()
