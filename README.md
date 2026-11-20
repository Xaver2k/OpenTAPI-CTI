# OpenTapiCti

Windows TAPI driver and CTI client for desk phones. Designed for applications such as THEORG to identify incoming callers and dial from patient records.

## Pilot status

Hardware compatibility and end-to-end operation with THEORG require validation. See [Anleitung.txt](Anleitung.txt) for workstation setup, device profiles and test procedures. Build the Windows x64 package using GitHub Actions. Use test numbers during initial setup.

## Windows download

Open [Windows builds](../../actions/workflows/windows.yml), select a successful run and download `OpenTapiCti-Windows-x64` under **Artifacts**. Extract the Windows package before starting the application. The package includes the GUI, the TAPI provider and setup scripts.
