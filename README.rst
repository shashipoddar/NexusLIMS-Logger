================
NexusLIMS-Logger
================


Logger (TKinter) GUI branched off from original NexusLIMS repository.


Run in command line
===================

1. Edit config file -- ``$HOME/nexuslims/gui/config.json``
2. ``python -m nexuslims_logger.main``

Packaging as a single executable
================================

Require ``pyinstaller`` installed. (``pip install pyinstaller``)

(under ``src/nexuslims_logger/``)

On Windows PowerShell::

    pyinstaller -y -F -w `
        -n "NexusLIMS Session Logger" `
        -i "resources\\logo_bare_xp.ico" `
        --add-data "resources;resources" main.py

On MacOS::

   pyinstaller -y -F -w \
       -n "NexusLIMS Session Logger" \
       -i "resources/logo_bare_xp.ico" \
       --add-data "resources:resources" main.py