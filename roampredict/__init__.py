"""RoamPredict: predictive Wi-Fi roaming assistant for Windows 10/11.

The package is split so that everything except ``platform/windows_wlan.py`` and
the Windows parts of ``net/l3.py`` runs on any OS.  That is what lets the
simulator and the tests exercise the real decision logic without Wi-Fi hardware.
"""

__version__ = "0.1.0"
