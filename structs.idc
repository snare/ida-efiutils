#define UNLOADED_FILE   1
#include <idc.idc>

static main(void)
{
  Enums();              // enumerations
  Structures();         // structure types
	LowVoids(0x1000);
	HighVoids(0x7A000);
}

//------------------------------------------------------------------------
// Information about enum types

static Enums(void) {
        auto id;
        BeginTypeUpdating(UTP_ENUM);
        EndTypeUpdating(UTP_ENUM);
}

static Structures_0(id) {
        auto mid;

	id = AddStrucEx(-1,"EFI_TABLE_HEADER",0);
	id = AddStrucEx(-1,"EFI_BOOT_SERVICES",0);
	id = AddStrucEx(-1,"EFI_RUNTIME_SERVICES",0);
	id = AddStrucEx(-1,"EFI_SYSTEM_TABLE",0);
	
	id = GetStrucIdByName("EFI_TABLE_HEADER");
	mid = AddStrucMember(id,"Signature",	0,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"Revision",	0X8,	0x20000400,	-1,	4);
	mid = AddStrucMember(id,"HeaderSize",	0XC,	0x20000400,	-1,	4);
	mid = AddStrucMember(id,"CRC32",	0X10,	0x20000400,	-1,	4);
	mid = AddStrucMember(id,"Reserved",	0X14,	0x20000400,	-1,	4);
	
	id = GetStrucIdByName("EFI_BOOT_SERVICES");
	mid = AddStrucMember(id,"Hdr",	0,	0x60000400,	GetStrucIdByName("EFI_TABLE_HEADER"),	24);
	mid = AddStrucMember(id,"RaiseTPL",	0X18,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"RestoreTPL",	0X20,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"AllocatePages",	0X28,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"FreePages",	0X30,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"GetMemoryMap",	0X38,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"AllocatePool",	0X40,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"FreePool",	0X48,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"CreateEvent",	0X50,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"SetTimer",	0X58,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"WaitForEvent",	0X60,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"SignalEvent",	0X68,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"CloseEvent",	0X70,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"CheckEvent",	0X78,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"InstallProtocolInterface",	0X80,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"ReinstallProtocolInterface",	0X88,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"UninstallProtocolInterface",	0X90,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"HandleProtocol",	0X98,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"Reserved",	0XA0,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"RegisterProtocolNotify",	0XA8,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"LocateHandle",	0XB0,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"LocateDevicePath",	0XB8,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"InstallConfigurationTable",	0XC0,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"LoadImage",	0XC8,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"StartImage",	0XD0,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"Exit",	0XD8,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"UnloadImage",	0XE0,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"ExitBootServices",	0XE8,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"GetNextMonotonicCount",	0XF0,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"Stall",	0XF8,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"SetWatchdogTimer",	0X100,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"ConnectController",	0X108,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"DisconnectController",	0X110,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"OpenProtocol",	0X118,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"CloseProtocol",	0X120,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"OpenProtocolInformation",	0X128,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"ProtocolsPerHandle",	0X130,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"LocateHandleBuffer",	0X138,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"LocateProtocol",	0X140,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"InstallMultipleProtocolInterfaces",	0X148,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"UninstallMultipleProtocolInterfaces",	0X150,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"CalculateCrc32",	0X158,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"CopyMem",	0X160,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"SetMem",	0X168,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"CreateEventEx",	0X170,	0x30000400,	-1,	8);
	
	id = GetStrucIdByName("EFI_RUNTIME_SERVICES");
	mid = AddStrucMember(id,"Hdr",	0,	0x60000400,	GetStrucIdByName("EFI_TABLE_HEADER"),	24);
	mid = AddStrucMember(id,"GetTime",	0X18,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"SetTime",	0X20,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"GetWakeupTime",	0X28,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"SetWakeupTime",	0X30,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"SetVirtualAddressMap",	0X38,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"ConvertPointer",	0X40,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"GetVariable",	0X48,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"GetNextVariableName",	0X50,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"SetVariable",	0X58,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"GetNextHighMonotonicCount",	0X60,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"ResetSystem",	0X68,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"UpdateCapsule",	0X70,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"QueryCapsuleCapabilities",	0X78,	0x30000400,	-1,	8);
	mid = AddStrucMember(id,"QueryVariableInfo",	0X80,	0x30000400,	-1,	8);
	
	id = GetStrucIdByName("EFI_SYSTEM_TABLE");
	mid = AddStrucMember(id,"Hdr",	0,	0x60000400,	GetStrucIdByName("EFI_TABLE_HEADER"),	24);
	mid = AddStrucMember(id,"FirmwareVendor",	0X18,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X18,	"CHAR16 *",	0);
	mid = AddStrucMember(id,"FirmwareRevision",	0X20,	0x20000400,	-1,	4);
	SetMemberComment(id,	0X20,	"UINT32",	0);
	mid = AddStrucMember(id,"ConsoleInHandle",	0X28,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X28,	"EFI_HANDLE",	0);
	mid = AddStrucMember(id,"ConIn",	0X30,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X30,	"EFI_SIMPLE_TEXT_INPUT_PROTOCOL *",	0);
	mid = AddStrucMember(id,"ConsoleOutHandle",	0X38,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X38,	"EFI_HANDLE",	0);
	mid = AddStrucMember(id,"ConOut",	0X40,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X40,	"EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *",	0);
	mid = AddStrucMember(id,"StandardErrorHandle",	0X48,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X48,	"EFI_HANDLE",	0);
	mid = AddStrucMember(id,"StdErr",	0X50,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X50,	"EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *",	0);
	mid = AddStrucMember(id,"RuntimeServices",	0X58,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X58,	"EFI_RUNTIME_SERVICES *",	0);
	mid = AddStrucMember(id,"BootServices",	0X60,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X60,	"EFI_BOOT_SERVICES *",	0);
	mid = AddStrucMember(id,"NumberOfTableEntries",	0X68,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X68,	"UINTN",	0);
	mid = AddStrucMember(id,"ConfigurationTable",	0X70,	0x30000400,	-1,	8);
	SetMemberComment(id,	0X70,	"EFI_CONFIGURATION_TABLE *",	0);
	return id;
}

//------------------------------------------------------------------------
// Information about structure types

static Structures(void) {
        auto id;
        BeginTypeUpdating(UTP_STRUCT);	id = Structures_0(id);
        EndTypeUpdating(UTP_STRUCT);
}

// End of file.
