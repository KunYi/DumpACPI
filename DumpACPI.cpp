// DumpACPI.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include ".\SysInfo\ISysInfo.h"
#include ".\SysInfo\ItemID.h"

typedef ISysInfo* (*_CreateSysInfo) (DWORD);
typedef void (*_DestroySysInfo) (ISysInfo*);
typedef ULONG	(*_MemReadBlock) (ULONG address, UCHAR* data, ULONG count, ULONG unitsize);
_MemReadBlock pfMemReadBlock = NULL;

#pragma pack(push)
#pragma pack(1)
typedef struct 
{
	UCHAR Signature[8];
	UCHAR Chksum;
	UCHAR OEMID[6];
	UCHAR Revision;
	ULONG pRSDT;
	ULONG Length;
	ULONG64 pXSDT;
	UCHAR XChksum;
	UCHAR Reserved[3];
} RSDP;

typedef struct
{
	UCHAR Signature[4];
	ULONG Length;
	UCHAR Revision;
	UCHAR Chksum;
	UCHAR OEMID[6];
	UCHAR OEMTID[8];
	ULONG OEMRev;
	ULONG CreatorID;
	ULONG CreatorRev;
} ACPI_TABLE_HEADER;

// Generic Address Structure, ref. Table 5-1 in ACPI spec.
typedef struct  
{
	UCHAR AddrSpace;
	UCHAR RegBitWidth;
	UCHAR RegBitOffset;
	UCHAR AccessSize;
	ULONG64 Addr;
} GAS;

// RSDP->RSDT->FADT
typedef struct 
{
	ACPI_TABLE_HEADER TableHeader;
	ULONG Firmware_Ctrl;
	ULONG pDSDT;
	UCHAR Revsered;
	UCHAR PeferredPMProfile;
	UINT16 SCI_INT;
	ULONG  SMI_CMD;
	UCHAR ACPI_ENABLE;
	UCHAR ACPI_DISABLE;
	UCHAR S4BIOS_REQ;
	UCHAR PSTAT_CNT;
	ULONG PM1a_EVT_BLK;
	ULONG PM1b_EVT_BLK;
	ULONG PM1a_CNT_BLK;
	ULONG PM1b_CNT_BLK;
	ULONG PM2_CNT_BLK;
	ULONG PM_TMR_BLK;
	ULONG GPE0_BLK;
	ULONG GPE1_BLK;
	UCHAR PM1_EVT_LEN;
	UCHAR PM1_CNT_LEN;
	UCHAR PM2_CNT_LEN;
	UCHAR PM_TMR_LEN;
	UCHAR GPE0_BLK_LEN;
	UCHAR GPE1_BLK_LEN;
	UCHAR GPE1_BASE;
	UCHAR CST_CNT;
	UINT16 P_LVL2_LAT;
	UINT16 P_LVL3_LAT;
	UINT16 FLUSH_SIZE;
	UINT16 FLUSH_STRIDE;
	UCHAR DUTY_OFFSET;
	UCHAR DUTY_WIDTH;
	UCHAR DAY_ALARM;
	UCHAR MONTH_ALARM;
	UCHAR CENTURY;
	UINT16 IAPC_BOOT_ARCH;
	UCHAR Reserved1;
	ULONG Flags;
	GAS	  RESET_REG;
	UCHAR RESET_VAL;
} FADT;

// RSDP->XSDT->XFADT
typedef struct  
{
	FADT fadt;
	UCHAR Reserved2[3];
	ULONG64 X_Firmware_CTRL;
	ULONG64 X_DSDT;
	GAS X_PM1a_EVT_BLK;
	GAS X_PM1b_EVT_BLK;
	GAS X_PM1a_CNT_BLK;
	GAS X_PM1b_CNT_BLK;
	GAS X_PM2_CNT_BLK;
	GAS X_PM_TMR_BLK;
	GAS X_GPE0_BLK;
	GAS X_GPE1_BLK;
} XFADT, *PXFADT;

// RSDP->RSDT->FADT->FACS
// RSDP->XSDT->XFADT->FACS
typedef struct {
	UCHAR Signature[4];
	ULONG Length;
	ULONG HWSignature;
	ULONG Firmware_Waking_Vector;
	ULONG Global_Lock;
	ULONG Flags;
	ULONG64 X_Firmware_Waking_Vector;
	UCHAR Version;
	UCHAR Reserved[31];
} FACS, *PFACS;

typedef struct {
	ACPI_TABLE_HEADER TableHeader;
	GAS	EC_CONTROL;
	GAS EC_DATA;
	ULONG UID;
	UCHAR GPE_BIT;
	UCHAR EC_ID[256];
} ECDT, *PECDT;

typedef struct {
	ACPI_TABLE_HEADER TableHeader;
	ULONG LocalAPICAddr;
	ULONG Flags;
} MADT, *PMADT;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UCHAR ProcessorID;
	UCHAR APICID;
	ULONG Flags;
} PROCESSOR_APIC, *PPROCESSOR_APIC;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UCHAR ID;
	UCHAR Reserved[3];
	ULONG Address;
	ULONG GlobalSystemINTBase;
} IOAPIC, *PIOAPIC;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UCHAR Bus;
	UCHAR Source;
	ULONG GlobalSystemINT;
	UINT16 Flags;
} INTSRC_OVERRIDE, *PINTSRC_OVERRIDE;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UINT16 Flags;
	ULONG GlobalSystemINT;
} NMI, *PNMI;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UCHAR ProcessorID;
	UINT16 Flags;
	UCHAR LINT;
} LNMI, *PLNMI;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UCHAR Reserved[2];
	ULONG64 Address;
} LAPIC_ADDRESS_OVERRIDE, *PLAPIC_ADDRESS_OVERRIDE;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UCHAR ID;
	UCHAR Reserved;
	ULONG GlobalSystemINTBase;
	ULONG64 Address;
} IO_SAPIC, *PIO_SAPIC;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UCHAR ProcessorID;
	UCHAR ID;
	UCHAR EID;
	UCHAR Reserved[3];
	ULONG Flags;
	ULONG ProcessUID;
	UCHAR UIDString[256];
} LSAPIC, *PLSAPIC;

typedef struct {
	UCHAR Type;
	UCHAR Length;
	UINT16 Flags;
	UCHAR INT_Type;
	UCHAR ProcessorID;
	UCHAR ProcessorEID;
	UCHAR IO_SAPIC_Vector;
	ULONG GlobalSystemINT;
	ULONG PlatformINTSrcFlags;
} PLATFORM_INT, *PPLATFORM_INT;

#pragma pack(pop)

enum { AT_PROCERROS_LAPIC = 0, AT_IOAPIC, AT_INTSRCO,
		AT_NMI, AT_LNMI, AT_LAPIC_ADDR_OVERRID,
		AT_IO_SAPIC, AT_LSAPIC, AT_PLATFORM_INT, AT_RESERVED
	};

bool LoadSysInfo(HMODULE &hSysInfoLib, ISysInfo* pISysInfo)
{
/*
 *  code snippet from
 *  https://stackoverflow.com/questions/1505582/determining-32-vs-64-bit-in-c
 *
 */
#if defined(ENV64BIT)
	TCHAR pSharedLibName[] = _T("SysInfoX64.dll");
#elif defined (ENV32BIT)
	TCHAR pSharedLibName[] = _T("SysInfo.dll");
#else
	// INCREASE ROBUSTNESS. ALWAYS THROW AN ERROR ON THE ELSE.
	// - What if I made a typo and checked for ENV6BIT instead of ENV64BIT?
	// - What if both ENV64BIT and ENV32BIT are not defined?
	// - What if project is corrupted, and _WIN64 and _WIN32 are not defined?
	// - What if I didn't include the required header file?
	// - What if I checked for _WIN32 first instead of second?
	//   (in Windows, both are defined in 64-bit, so this will break codebase)
	// - What if the code has just been ported to a different OS?
	// - What if there is an unknown unknown, not mentioned in this list so far?
	// I'm only human, and the mistakes above would break the *entire* codebase.
#error "Must define either ENV32BIT or ENV64BIT"
#endif
	hSysInfoLib = LoadLibrary(pSharedLibName);

	if (NULL != hSysInfoLib)
	{
		_CreateSysInfo pCreateSysInfo = (_CreateSysInfo)GetProcAddress(hSysInfoLib, "CreateSysInfo");

		if (NULL != pCreateSysInfo)
		{
			pISysInfo = pCreateSysInfo(MODE_PCI); // request access memory spaces, MODE_PCI
		}
		else
		{
			printf("ERR: Failed in GetProcAddress(\"CreateSysInfo\")\n");
			exit(-1);
			return false;
		}
	}
	else 
	{
		printf("Can't find %s\n", pSharedLibName);
		exit(-1);
		return false;
	}
	return true;
}

bool UnloadSysInfo(HMODULE hSysInfoLib, ISysInfo* pISysInfo)
{
	_DestroySysInfo pDestroySysInfo = (_DestroySysInfo)GetProcAddress(hSysInfoLib, "DestroySysInfo");
	if (pDestroySysInfo)
	{
		pDestroySysInfo(pISysInfo);
		pISysInfo = NULL;
	}
	else
	{
		printf("ERR: Failed in GetProcAddress(\"DestroySysInfo\")\n");
		exit(-1);
		return false;
	}
		
	FreeLibrary(hSysInfoLib);
	hSysInfoLib = NULL;
	return true;
}

UCHAR* toString(const UCHAR* src, int len)
{
	static UCHAR buff[256];
	memcpy(buff, src, len);
	buff[len] = 0;
	return buff;
}

const char* strPMProfile(UCHAR val)
{
	const char* strProfile[9] = {
		"Unspecified",
		"Desktop",
		"Mobile",
		"Workstation",
		"Enterprise Server",
		"SOHO Server",
		"Appliance PC",
		"Performance Server",
		"Reserved",
	};

	if(val > 8) val = 8;

	return strProfile[val];
}

const char* strAddrSpace(UCHAR val)
{
	const char* strSpace[5] = {
		"Memory",
		"I/O",
		"PCI Configuration",
		"Function Fix Hardware",
		"Reserved"
	};

	if (val == 3) val = 5;
	if (val == 0x7F) val = 3;
	if (val > 4) val = 5;

	return strSpace[val];
}

void printRSDP(RSDP *pRSDP)
{
	printf("CheckSum: 0x%X\n", pRSDP->Chksum);
	printf("OEM ID: %s\n", toString(pRSDP->OEMID,6));
	printf("Revision: 0x%X\n", pRSDP->Revision);
	printf("RSDT Address: 0x%X\n", pRSDP->pRSDT);
	printf("Length of the Table: %d(0x%X)\n", pRSDP->Length, pRSDP->Length);
	printf("XSDT Address: %#I64X\n", pRSDP->pXSDT);
	printf("Extended Checksum 0x%X\n", pRSDP->XChksum);
}

void printACPITableHeader(ACPI_TABLE_HEADER &table,ULONG addr)
{
	printf("-==================================================-\n");
	printf("Table: %s, at 0x%X\n", toString(table.Signature, 4), addr);
	printf("Length of the Table: %d\n", table.Length);
	printf("Revision: 0x%X\n", table.Revision);
	printf("Checksum: 0x%X\n", table.Chksum);
	printf("OEMID: %s\n", toString(table.OEMID, 6));
	printf("OEM Table ID: %s\n", toString(table.OEMTID, 8));
	printf("OEM Revision: 0x%X\n",table.OEMRev);
	printf("Creator ID: %s\n", toString((UCHAR*)&table.CreatorID, 4));
	printf("Creator Revision 0x%X\n", table.CreatorRev);
}

void printRSDT(ACPI_TABLE_HEADER &RSDT, ULONG addr)
{
	printACPITableHeader(RSDT, addr);
	printf("Entry count : %zd\n", (RSDT.Length-sizeof(ACPI_TABLE_HEADER))/4);
}

void printXSDT(ACPI_TABLE_HEADER &XSDT, ULONG addr)
{
	printACPITableHeader(XSDT, addr);
	printf("Entry count : %zd\n", (XSDT.Length-sizeof(ACPI_TABLE_HEADER))/8);
}

void printGAS(GAS &gas, const char* prefix)
{
	printf("%sAddress Space: %s(%d)\n", prefix,
		strAddrSpace(gas.AddrSpace), gas.AddrSpace);
	printf("%sBitWidth: 0x%X,\n", prefix, gas.RegBitWidth);
	printf("%sBitOffset: 0x%X,\n", prefix, gas.RegBitOffset);
	printf("%sAccessSize: 0x%X, \n", prefix, gas.AccessSize);
	printf("%sAddress:0x%llX\n",	prefix, gas.Addr);
}

void printFADT(FADT& fadt)
{
	printf("  Firmware Ctrl(FACS): 0x%X\n", fadt.Firmware_Ctrl);
	printf("  DSDT: 0x%X\n", fadt.pDSDT);
	printf("  Peferred_PM_Profile:%s(%d)\n", 
		strPMProfile(fadt.PeferredPMProfile), fadt.PeferredPMProfile);
	printf("  SCI_INT: %d(0x%X)\n", fadt.SCI_INT, fadt.SCI_INT);
	printf("  SMI_CMD: %d(0x%X)\n", fadt.SMI_CMD, fadt.SMI_CMD);
	printf("  ACPI_ENABLE: 0x%X\n", fadt.ACPI_ENABLE);
	printf("  ACPI_DISABLE: 0x%X\n", fadt.ACPI_DISABLE);
	printf("  S4BIOS_REQ: 0x%X\n", fadt.S4BIOS_REQ);
	printf("  PSTAT_CNT: 0x%X\n", fadt.PSTAT_CNT);
	printf("  PM1a_EVT_BLK: 0x%X\n", fadt.PM1a_EVT_BLK);
	printf("  PM1b_EVT_BLK: 0x%X\n", fadt.PM1b_EVT_BLK);
	printf("  PM1a_CNT_BLK: 0x%X\n", fadt.PM1a_CNT_BLK);
	printf("  PM1b_CNT_BLK: 0x%X\n", fadt.PM1b_CNT_BLK);
	printf("  PM2_CNT_BLK: 0x%X\n", fadt.PM2_CNT_BLK);
	printf("  PM_TMR_BLK: 0x%X\n", fadt.PM_TMR_BLK);
	printf("  GPE0_BLK: 0x%X\n", fadt.GPE0_BLK);
	printf("  GPE1_BLK: 0x%X\n", fadt.GPE1_BLK);
	printf("  PM1_EVT_LEN: 0x%X\n", fadt.PM1_EVT_LEN);
	printf("  PM1_CNT_LEN: 0x%X\n", fadt.PM1_CNT_LEN);
	printf("  PM2_CNT_LEN: 0x%X\n", fadt.PM2_CNT_LEN);
	printf("  PM_TMR_LEN: 0x%X\n", fadt.PM_TMR_LEN);
	printf("  GPE0_BLK_LEN: 0x%X\n", fadt.GPE0_BLK_LEN);
	printf("  GPE1_BLK_LEN: 0x%X\n", fadt.GPE1_BLK_LEN);
	printf("  GPE1_BASE: 0x%X\n", fadt.GPE1_BASE);
	printf("  CST_CNT: 0x%X\n", fadt.CST_CNT);
	printf("  P_LVL2_LAT: 0x%X\n", fadt.P_LVL2_LAT);
	printf("  P_LVL3_LAT: 0x%X\n", fadt.P_LVL3_LAT);
	printf("  FLUSH_SIZE: 0x%X\n", fadt.FLUSH_SIZE);
	printf("  FLUSH_STRIDE: 0x%X\n", fadt.FLUSH_STRIDE);
	printf("  Duty Offset: 0x%X\n", fadt.DUTY_OFFSET);
	printf("  Duty Width: 0x%X\n", fadt.DUTY_WIDTH);
	printf("  Day Alarm: %d\n", fadt.DAY_ALARM);
	printf("  Month Alarm: %d\n", fadt.MONTH_ALARM);
	printf("  Century: 0x%X\n", fadt.CENTURY);
	printf("  IA Boot Architecture: 0x%X\n", fadt.IAPC_BOOT_ARCH);
	printf("  Flags: 0x%X\n", fadt.Flags);
		// Todo here, need to parse flags
	printf("  RESET Reg:\n");
	printGAS(fadt.RESET_REG, "    ");
	printf("  Reset Val: 0x%X\n", fadt.RESET_VAL);
}

void printXFADT(XFADT& xfadt)
{
	printFADT(xfadt.fadt);
	printf("  X_Firmware_CTRL(FACS): 0x%llX\n", xfadt.X_Firmware_CTRL);
	printf("  X_DSDT: 0x%llX\n", xfadt.X_DSDT);
	printf("  X_PM1a_EVT_BLK:\n");
	printGAS(xfadt.X_PM1a_EVT_BLK, "    ");
	printf("  X_PM1b_EVT_BLK:\n");
	printGAS(xfadt.X_PM1b_EVT_BLK, "    ");
	printf("  X_PM1a_CNT_BLK:\n");
	printGAS(xfadt.X_PM1a_CNT_BLK, "    ");
	printf("  X_PM1b_CNT_BLK:\n");
	printGAS(xfadt.X_PM1b_CNT_BLK, "    ");
	printf("  X_PM2_CNT_BLK:\n");
	printGAS(xfadt.X_PM2_CNT_BLK, "    ");
	printf("  X_PM_TMR_BLK:\n");
	printGAS(xfadt.X_PM_TMR_BLK, "    ");
	printf("  X_GPE0_BLK:\n");
	printGAS(xfadt.X_GPE0_BLK, "    ");
	printf("  X_GPE1_BLK:\n");
	printGAS(xfadt.X_GPE1_BLK, "    ");
}

void printFACS(FACS& table, ULONG addr)
{
	printf("-==================================================-\n");
	printf("Table: %s, at 0x%X\n", toString(table.Signature, 4), addr);
	printf("Length of the Table: %d\n", table.Length);
	printf("HWSignature: 0x%X\n", table.HWSignature);
	printf("Firmware Waking Vector: 0x%X\n", table.Firmware_Waking_Vector);
	printf("Global Lock: 0x%X\n", table.Global_Lock);
	printf("Flags: 0x%X\n", table.Flags);
	printf("X Firmware Waking Vector: 0x%llX\n", table.X_Firmware_Waking_Vector);
	printf("Version: 0x%X\n", table.Version);
}

void printECDT(ECDT& ecdt, ULONG addr)
{
	printACPITableHeader(ecdt.TableHeader, addr);
	printf("EC CONTROL:\n");
	printGAS(ecdt.EC_CONTROL, "  ");
	printf("EC DATA:\n");
	printGAS(ecdt.EC_DATA, "  ");
	printf("UID: 0x%X\n", ecdt.UID);
	printf("GPE BIT: 0x%X\n", ecdt.GPE_BIT);
	printf("EC ID: %s\n", ecdt.EC_ID);
}

void printMADT(MADT& madt, ULONG addr)
{
	printACPITableHeader(madt.TableHeader, addr);
	printf("Local APIC Address: 0x%X\n", madt.LocalAPICAddr);
	printf("Flags: 0x%X\n", madt.Flags);
}

bool DumpDSDT(ULONG addr)
{
	ACPI_TABLE_HEADER dsdt;
	UCHAR *pBuff;
	
	pfMemReadBlock(addr, (UCHAR*)&dsdt, sizeof(dsdt), 1);
	printACPITableHeader(dsdt, addr);
	pBuff =(UCHAR*) malloc(dsdt.Length);
	
	if (NULL == pBuff )
	{
		printf("Warring: Can't dump DSDT.aml. due to memory allocate failed\n");
		return false;
	}

	pfMemReadBlock(addr, pBuff, dsdt.Length, 1);
	
	// write to file
	FILE *fp = NULL;
	fopen_s(&fp, "dsdt.aml", "wb"); // write/binary mode
	fwrite(pBuff, dsdt.Length, 1,fp);
	fclose(fp);
	free(pBuff);
	return true;
}

void ProcFACS(ULONG addr)
{
	FACS facs;
	pfMemReadBlock(addr, (UCHAR*)&facs, sizeof(facs), 1);
	printFACS(facs, addr);
}


bool ProcFADT(ACPI_TABLE_HEADER& table, ULONG addr)
{
	XFADT xfadt;
	UINT size = table.Length;

	memset(&xfadt, 0, sizeof(XFADT));

	if (table.Length > sizeof(XFADT))
	{
		printf("Warring: unknown size of FADT\n");
		size = sizeof(XFADT);
	}

	pfMemReadBlock(addr, (UCHAR*)&xfadt, size, 1);
	
	printACPITableHeader(xfadt.fadt.TableHeader, addr);
	if(table.Length > sizeof(FADT))
	{
		printXFADT(xfadt);
	}
	else
	{
		printFADT(xfadt.fadt);
	}
	
	// Dump DSDT table
	DumpDSDT(xfadt.fadt.pDSDT);
	ProcFACS(xfadt.fadt.Firmware_Ctrl);
	return true;
}

void DumpSSDT(ACPI_TABLE_HEADER& table, ULONG addr)
{
	// Todo, Here!
}

bool ProcSSDT(ACPI_TABLE_HEADER& table, ULONG addr)
{
	printACPITableHeader(table, addr);
	DumpSSDT(table, addr);
	return true;
}


bool ProcECDT(ACPI_TABLE_HEADER& table, ULONG addr)
{
	ECDT ecdt;
	UINT size = table.Length;

	if (size > sizeof(ECDT))
	{
		size = sizeof(ECDT) - 1;
		printf("Warring: the ECDT table over size!\n");
	}

	pfMemReadBlock(addr, (UCHAR*)&ecdt, size, 1);
	ecdt.EC_ID[255] = 0;

	printECDT(ecdt, addr);
	return true;
}

bool ProcMADT(ACPI_TABLE_HEADER& table, ULONG addr)
{
	MADT madt;
	UCHAR buff[256];
	UCHAR *p;

	UINT  size = table.Length-sizeof(MADT);
	
	pfMemReadBlock(addr, (UCHAR*)&madt, sizeof(MADT), 1);
	
	if (size > sizeof(buff))
	{
		size = sizeof(buff);
	}

	pfMemReadBlock(addr+sizeof(MADT), buff, size, 1);
	printMADT(madt, addr);
	
	p = buff;

	for (UINT i=0; i < size; i += *(p+1), p += *(p+1))
	{
		switch(*p) {
		case AT_PROCERROS_LAPIC: // Processor Local APIC
			{
				PPROCESSOR_APIC papic = (PPROCESSOR_APIC)p;
				printf("  -------------------------------------------------\n");
				printf("  Processor APIC, Type: %d\n", papic->Type);
				printf("  Length: %d\n", papic->Length);
				printf("  Processor ID: 0x%X\n", papic->ProcessorID);
				printf("  APIC ID: 0x%X\n", papic->APICID);
				printf("  Flags: 0x%X\n",papic->Flags);
			}
			break;
		case AT_IOAPIC:  // I/O APIC
			{
				PIOAPIC pioapic = (PIOAPIC)p;
				printf("  -------------------------------------------------\n");
				printf("  I/O APIC, Type: %d\n", pioapic->Type);
				printf("  Length: %d\n", pioapic->Length);
				printf("  I/O APIC ID: 0x%X\n", pioapic->ID);
				printf("  I/O APIC Address: 0x%X\n", pioapic->Address );
				printf("  Global System Interrupt Base: 0x%X\n", pioapic->GlobalSystemINTBase);
			}
			break;
		case AT_INTSRCO: 
			// Interrupt source override
			break;
		case AT_NMI: 
			// Non-maskable interrupt source
			break;
		case AT_LNMI:
			break;
		case AT_LAPIC_ADDR_OVERRID:
			break;
		case AT_IO_SAPIC:
			break;
		case AT_LSAPIC:
			break;
		case AT_PLATFORM_INT:
			break;
		}
	}

	return true;
}

bool ProcBOOT(ACPI_TABLE_HEADER& table, ULONG addr)
{
	printACPITableHeader(table, addr);
	printf("Warring: Todo, Here! need check Microsoft Simple Boot Flag Specification.\n");
	return true;
}

bool DispatchACPITable(ACPI_TABLE_HEADER& table, ULONG addr)
{
	typedef struct  
	{
		UCHAR SIGN[4];
		bool (*ProcFunc) (ACPI_TABLE_HEADER& table, ULONG addr);
	} ProcTable;

	ProcTable pTEntry[] = { 
		{ {'F', 'A', 'C', 'P'}, ProcFADT },
		{ {'S', 'S', 'D', 'T'}, ProcSSDT },
		{ {'E', 'C', 'D', 'T'}, ProcECDT },
		{ {'A', 'P', 'I', 'C'}, ProcMADT },
		// { {'M', 'C', 'F', 'G'}, ProcMCFG },
		// { {'H', 'P', 'E', 'T'}, ProcHPET },
		{ {'B', 'O', 'O', 'T'}, ProcBOOT },
	};

	for (int i = 0; i < sizeof(pTEntry)/sizeof(ProcTable); i++)
	{
		if (0 == memcmp(pTEntry[i].SIGN, table.Signature, 4))
		{
			pTEntry[i].ProcFunc(table, addr);
			return true;
		}
	}

	return false;
}
int _tmain(int argc, _TCHAR* argv[])
{
	ISysInfo* pISysInfo = NULL;
	HMODULE hSysInfoLib = NULL;
	const ULONG MEM_RANGE = 64*1024*2; // 0xE0000 ~ 0xFFFFF, segment 64K x 2
	const ULONG MEM_START = 0xE0000;
	UCHAR buff[MEM_RANGE];
	
	if (false == LoadSysInfo(hSysInfoLib, pISysInfo))
		return -1;

	pfMemReadBlock = (_MemReadBlock) GetProcAddress(hSysInfoLib, "_MemReadBlock");
	if (pfMemReadBlock)
	{
		pfMemReadBlock(MEM_START, buff, MEM_RANGE, sizeof(UCHAR));
	}
	else
	{
		printf("ERR: failed in GetProcAddress(\"_MemReadBlock\")\n");
	}
	
	if (pfMemReadBlock)
	{
		UCHAR *p = buff;
		RSDP * pRSDP = NULL;
		for (int i = 0; i < MEM_RANGE; i+=16)
		{
			if (0 == memcmp(p, "RSD PTR ", 8))
			{
				// Calc chksum, 
				// This includes only the first 20 bytes of this table, 
				// bytes 0 to 19, including the checksum field. 
				// These bytes must sum to zero.
				UCHAR chksum = 0;
				for(UCHAR *pc = p; pc < p+20; pc++)
				{
					chksum += *pc;
				}

				if (0 == chksum)
				{
					pRSDP = (RSDP*)p;
					printf("Find the Root System Description Table at 0x%X\n",MEM_START+i);
					printRSDP(pRSDP);
				}			
				// find out RSDP
				if (pRSDP)
				{
					ACPI_TABLE_HEADER RSDT;
					ACPI_TABLE_HEADER XSDT;
					
					pfMemReadBlock(pRSDP->pRSDT, (UCHAR*)&RSDT, sizeof(RSDT), 1);
					printRSDT(RSDT, pRSDP->pRSDT);
					
					ULONG Entry[64];
					int n = 0;

					// Warring!! should use x64 driver to get 64bits address, 
					// but SysInfo 32/x64 driver only implement access 32bit spaces
					if (pRSDP->pXSDT < 0x100000000)
					{
						pfMemReadBlock((ULONG)pRSDP->pXSDT, (UCHAR*)&XSDT, sizeof(XSDT), 1);
						printXSDT(XSDT, (ULONG)pRSDP->pXSDT);
						n = (XSDT.Length - sizeof(ACPI_TABLE_HEADER))/8;
						if (n > 64) n = 64;
						
						ULONG64 Entry64[64];
						pfMemReadBlock((ULONG)pRSDP->pXSDT + sizeof(ACPI_TABLE_HEADER), 
							(UCHAR*)&Entry64[0], 8*n, 1);

						int j = 0;
						for (int i = 0; i < n; i++)
						{
							if (Entry64[i] < 0x100000000)
							{
								Entry[i] = (ULONG)Entry64[i];
								j++;
							}
							else
							{
								printf("Warring!! The entry address(%#I64X) > 4GB\n", Entry64[i]);
							}
						}
						n = j;
					}
					else
					{
						printf("!!!!!! XSDT in over 4G space !!!!!!\n");
						// use RSDP to get table entry
						int n = (RSDT.Length - sizeof(ACPI_TABLE_HEADER))/4;
						if (n > 64) n = 64; // limit max. 63;
						pfMemReadBlock(pRSDP->pRSDT + sizeof(ACPI_TABLE_HEADER), 
							(UCHAR*)&Entry[0], 4*n, 1);
					}

					ACPI_TABLE_HEADER ACPITab;
					for (int i = 0; i < n; i++)
					{
						pfMemReadBlock(Entry[i], (UCHAR*)&ACPITab, sizeof(ACPI_TABLE_HEADER), 1);
						if (!DispatchACPITable(ACPITab, Entry[i]))
						{
							printACPITableHeader(ACPITab, Entry[i]);
						}
					}
				}
				break;
			}
			p+=16;
		}
		

	}

	UnloadSysInfo(hSysInfoLib, pISysInfo);
	return 0;
}

