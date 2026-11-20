# OpenTapiCti

Windows TAPI driver and CTI client for desk phones. Provides caller information and dialing to compatible TAPI applications.

## Pilot status

Hardware compatibility and end-to-end operation with individual TAPI applications require validation. See [Anleitung.txt](Anleitung.txt) for workstation setup, device profiles and test procedures. Build the Windows x64 package using GitHub Actions. Use test numbers during initial setup.

## Windows download

Open [Windows builds](../../actions/workflows/windows.yml), select a successful run and download `OpenTapiCti-Windows-x64` under **Artifacts**. Extract the Windows package before starting the application. The package includes the GUI, the TAPI provider and setup scripts.
