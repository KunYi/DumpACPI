# DumpACPI

---
the code just for ACPI study

just dump dsdt.aml into execute folder
then run microsoft asl compiler to dissamble AML to ASL (asl.exe /u dsdt.aml)
or try asl.exe /tab=DSDT to get DSDT.ASL

---
Tips:
1. need administrator privileges
2. tested on XP/Win7/Win10 passed

reference.
[Microsoft ASL](https://docs.microsoft.com/en-us/windows-hardware/drivers/bringup/microsoft-asl-compiler)
