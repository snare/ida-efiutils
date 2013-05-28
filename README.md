# EFI scripts for IDA Pro

Some IDA scripts to assist with reverse engineering EFI executables.

This package contains the following files:

1. `efiutils.py` - IDAPython module with some helper functions

2. `efiguids.py` - A collection of known GUIDs for EFI protocols

3. `efiguids_ami.py` - A collection of known GUIDs for protocols used in the AMI BIOS

4. `behemoth.h` - A giant header containing a collection of type and structure definitions for EFI

5. `structs.idc` - An IDC script containing some struct definitions (superseded by `behemoth.h`)

6. `te_image.bt` - An 010 Editor template for TE binary images

7. `te_loader.py` - An IDA Pro loader script for TE binary images

This is my first attempt at IDA scripting, so please forgive me and let me know if I've reinvented wheels/done anything silly.

## Functions

The main useful functions are described below. See code and docstrings for more information on other functions.

### `rename_tables()`

Finds the first entry point for the binary, tries to track the parameters that were passed to the entry point function and rename global variables in which the key EFI tables are stored. The following renaming operations are performed:

1. Global where `ImageHandle` ends up is renamed to `gImageHandle`.

2. Global where `SystemTable` ends up is renamed to `gSystemTable`.

3. Global where `SystemTable->BootServices` ends up is renamed to `gBootServices`.

4. Global where `SystemTable->RuntimeServices` ends up is renamed to `gRuntimeServices`.

Call instructions will only be followed one level deep, as most executables copy the table references in the entry point or a function called from the entry point. Change `MAX_STACK_DEPTH` if necessary.

### `update_structs()`

Finds cross-references to tables renamed above, and updates their names to be struct offsets from the appropriate structs. If `rename_tables()` failed you'll need to rename things manually as above for this to work properly.


For example:

	    mov     rax, cs:qword_whatever
	    call    qword ptr [rax+150h]

Becomes:

	    mov     rax, cs:gBootServices
	    call    [rax+EFI_BOOT_SERVICES.UninstallMultipleProtocolInterfaces]

### `rename_guids()`

Finds GUIDs in data segments and renames them. 470 protocol GUIDs were pulled out of the TianoCore source, and proprietary Apple (and other vendor) GUIDs will be added as they are encountered.

### `go()`

Convenience method that does all of the above. 

## Usage

1. Load up your EFI binary in IDA Pro

2. Import `behemoth.h` to define the necessary data structures

3. Add the structures from local types to your IDB

4. Run `efiutils.py` to add it to python's path (or do this by some other method)

5. Have a look at the code/docstrings, but probably:

		import efiutils; efiutils.go()

To use the `te_loader.py` TE image loader, install it as you would any other loader. On OS X this is done by copying or symlinking it inside the loaders folder at `idaq.app/Contents/MacOS/loaders/`.
