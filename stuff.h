#ifndef STUFF_H
#define STUFF_H

#include <stdint.h>

typedef int	cpu_type_t;
typedef int	cpu_subtype_t;

#define FAT_MAGIC	0xcafebabe
#define FAT_CIGAM	0xbebafeca /* NXSwapLong(FAT_MAGIC) */

#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe /* NXSwapInt(MH_MAGIC) */

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */

#define CPU_TYPE_I386		((cpu_type_t)7)
#define CPU_ARCH_ABI64		0x1000000
#define CPU_TYPE_X86_64		((cpu_type_t)(CPU_TYPE_I386 | CPU_ARCH_ABI64))

struct fat_header
{
  uint32_t magic;
  uint32_t nfat_arch;
};

struct fat_arch
{
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t offset;
  uint32_t size;
  uint32_t align;
};

struct mach_header
{
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
};

struct mach_header_64
{
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
};

struct load_command
{
  uint32_t cmd;
  uint32_t cmdsize;
};

struct segment_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint32_t vmaddr;
  uint32_t vmsize;
  uint32_t fileoff;
  uint32_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct segment_command_64
{
    uint32_t	cmd;
    uint32_t	cmdsize;
    char		segname[16];
    uint64_t	vmaddr;
    uint64_t	vmsize;
    uint64_t	fileoff;
    uint64_t	filesize;
    uint32_t	maxprot;
    uint32_t	initprot;
    uint32_t	nsects;
    uint32_t	flags;
};

struct section
{
  char sectname[16];
  char segname[16];
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
};

struct section_64
{ /* for 64-bit architectures */
    char		sectname[16];	/* name of this section */
    char		segname[16];	/* segment this section goes in */
    uint64_t	addr;		/* memory address of this section */
    uint64_t	size;		/* size in bytes of this section */
    uint32_t	offset;		/* file offset of this section */
    uint32_t	align;		/* section alignment (power of 2) */
    uint32_t	reloff;		/* file offset of relocation entries */
    uint32_t	nreloc;		/* number of relocation entries */
    uint32_t	flags;		/* flags (section type and attributes)*/
    uint32_t	reserved1;	/* reserved (for offset or index) */
    uint32_t	reserved2;	/* reserved (for count or sizeof) */
    uint32_t	reserved3;	/* reserved */
};

struct symtab_command
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t symoff;
  uint32_t nsyms;
  uint32_t stroff;
  uint32_t strsize;
};

struct nlist
{
  union
  {
    #ifndef __LP64__
      char *n_name;
    #endif
      int32_t n_strx;
  } n_un;
  uint8_t n_type;
  uint8_t n_sect;
  int16_t n_desc;
  uint32_t n_value;
};

struct nlist_64
{
    union
    {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
};

/*
 * After MacOS X 10.1 when a new load command is added that is required to be
 * understood by the dynamic linker for the image to execute properly the
 * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
 * linker sees such a load command it it does not understand will issue a
 * "unknown load command required for execution" error and refuse to use the
 * image.  Other load commands without this bit that are not understood will
 * simply be ignored.
 */
#define LC_REQ_DYLD 0x80000000

/* Constants for the cmd field of all load commands, the type */
#define	LC_SEGMENT	0x1	/* segment of this file to be mapped */
#define	LC_SYMTAB	0x2	/* link-edit stab symbol table info */
#define	LC_SYMSEG	0x3	/* link-edit gdb symbol table info (obsolete) */
#define	LC_THREAD	0x4	/* thread */
#define	LC_UNIXTHREAD	0x5	/* unix thread (includes a stack) */
#define	LC_LOADFVMLIB	0x6	/* load a specified fixed VM shared library */
#define	LC_IDFVMLIB	0x7	/* fixed VM shared library identification */
#define	LC_IDENT	0x8	/* object identification info (obsolete) */
#define LC_FVMFILE	0x9	/* fixed VM file inclusion (internal use) */
#define LC_PREPAGE      0xa     /* prepage command (internal use) */
#define	LC_DYSYMTAB	0xb	/* dynamic link-edit symbol table info */
#define	LC_LOAD_DYLIB	0xc	/* load a dynamically linked shared library */
#define	LC_ID_DYLIB	0xd	/* dynamically linked shared lib ident */
#define LC_LOAD_DYLINKER 0xe	/* load a dynamic linker */
#define LC_ID_DYLINKER	0xf	/* dynamic linker identification */
#define	LC_PREBOUND_DYLIB 0x10	/* modules prebound for a dynamically */
                                /*  linked shared library */
#define	LC_ROUTINES	0x11	/* image routines */
#define	LC_SUB_FRAMEWORK 0x12	/* sub framework */
#define	LC_SUB_UMBRELLA 0x13	/* sub umbrella */
#define	LC_SUB_CLIENT	0x14	/* sub client */
#define	LC_SUB_LIBRARY  0x15	/* sub library */
#define	LC_TWOLEVEL_HINTS 0x16	/* two-level namespace lookup hints */
#define	LC_PREBIND_CKSUM  0x17	/* prebind checksum */

/*
 * load a dynamically linked shared library that is allowed to be missing
 * (all symbols are weak imported).
 */
#define	LC_LOAD_WEAK_DYLIB (0x18 | LC_REQ_DYLD)

#define	LC_SEGMENT_64	0x19	/* 64-bit segment of this file to be
                                   mapped */
#define	LC_ROUTINES_64	0x1a	/* 64-bit image routines */
#define LC_UUID		0x1b	/* the uuid */
#define LC_RPATH       (0x1c | LC_REQ_DYLD)    /* runpath additions */
#define LC_CODE_SIGNATURE 0x1d	/* local of code signature */
#define LC_SEGMENT_SPLIT_INFO 0x1e /* local of info to split segments */
#define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD) /* load and re-export dylib */
#define	LC_LAZY_LOAD_DYLIB 0x20	/* delay load of dylib until first use */
#define	LC_ENCRYPTION_INFO 0x21	/* encrypted segment information */
#define	LC_DYLD_INFO 	0x22	/* compressed dyld information */
#define	LC_DYLD_INFO_ONLY (0x22|LC_REQ_DYLD)	/* compressed dyld information only */

#define	N_STAB	0xe0  /* if any of these bits set, a symbolic debugging entry */
#define	N_PEXT	0x10  /* private external symbol bit */
#define	N_TYPE	0x0e  /* mask for the type bits */
#define	N_EXT	0x01  /* external symbol bit, set for external symbols */

/*
 * Only symbolic debugging entries have some of the N_STAB bits set and if any
 * of these bits are set then it is a symbolic debugging entry (a stab).  In
 * which case then the values of the n_type field (the entire field) are given
 * in <mach-o/stab.h>
 */

/*
 * Values for N_TYPE bits of the n_type field.
 */
#define	N_UNDF	0x0		/* undefined, n_sect == NO_SECT */
#define	N_ABS	0x2		/* absolute, n_sect == NO_SECT */
#define	N_SECT	0xe		/* defined in section number n_sect */
#define	N_PBUD	0xc		/* prebound undefined (defined in a dylib) */
#define N_INDR	0xa		/* indirect */

/*
 * If the type is N_INDR then the symbol is defined to be the same as another
 * symbol.  In this case the n_value field is an index into the string table
 * of the other symbol's name.  When the other symbol is defined then they both
 * take on the defined type and value.
 */

/*
 * If the type is N_SECT then the n_sect field contains an ordinal of the
 * section the symbol is defined in.  The sections are numbered from 1 and
 * refer to sections in order they appear in the load commands for the file
 * they are in.  This means the same ordinal may very well refer to different
 * sections in different files.
 *
 * The n_value field for all symbol table entries (including N_STAB's) gets
 * updated by the link editor based on the value of it's n_sect field and where
 * the section n_sect references gets relocated.  If the value of the n_sect
 * field is NO_SECT then it's n_value field is not changed by the link editor.
 */
#define	NO_SECT		0	/* symbol is not in any section */
#define MAX_SECT	255	/* 1 thru 255 inclusive */

#define	N_GSYM	0x20	/* global symbol: name,,NO_SECT,type,0 */
#define	N_FNAME	0x22	/* procedure name (f77 kludge): name,,NO_SECT,0,0 */
#define	N_FUN	0x24	/* procedure: name,,n_sect,linenumber,address */
#define	N_STSYM	0x26	/* static symbol: name,,n_sect,type,address */
#define	N_LCSYM	0x28	/* .lcomm symbol: name,,n_sect,type,address */
#define N_BNSYM 0x2e	/* begin nsect sym: 0,,n_sect,0,address */
#define N_AST	0x32	/* AST file path: name,,NO_SECT,0,0 */
#define N_OPT	0x3c	/* emitted with gcc2_compiled and in gcc source */
#define	N_RSYM	0x40	/* register sym: name,,NO_SECT,type,register */
#define	N_SLINE	0x44	/* src line: 0,,n_sect,linenumber,address */
#define N_ENSYM 0x4e	/* end nsect sym: 0,,n_sect,0,address */
#define	N_SSYM	0x60	/* structure elt: name,,NO_SECT,type,struct_offset */
#define	N_SO	0x64	/* source file name: name,,n_sect,0,address */
#define	N_OSO	0x66	/* object file name: name,,0,0,st_mtime */
#define	N_LSYM	0x80	/* local sym: name,,NO_SECT,type,offset */
#define N_BINCL	0x82	/* include file beginning: name,,NO_SECT,0,sum */
#define	N_SOL	0x84	/* #included file name: name,,n_sect,0,address */
#define	N_PARAMS  0x86	/* compiler parameters: name,,NO_SECT,0,0 */
#define	N_VERSION 0x88	/* compiler version: name,,NO_SECT,0,0 */
#define	N_OLEVEL  0x8A	/* compiler -O level: name,,NO_SECT,0,0 */
#define	N_PSYM	0xa0	/* parameter: name,,NO_SECT,type,offset */
#define N_EINCL	0xa2	/* include file end: name,,NO_SECT,0,0 */
#define	N_ENTRY	0xa4	/* alternate entry: name,,n_sect,linenumber,address */
#define	N_LBRAC	0xc0	/* left bracket: 0,,NO_SECT,nesting level,address */
#define N_EXCL	0xc2	/* deleted include file: name,,NO_SECT,0,sum */
#define	N_RBRAC	0xe0	/* right bracket: 0,,NO_SECT,nesting level,address */
#define	N_BCOMM	0xe2	/* begin common: name,,NO_SECT,0,0 */
#define	N_ECOMM	0xe4	/* end common: name,,n_sect,0,0 */
#define	N_ECOML	0xe8	/* end common (local name): 0,,n_sect,0,address */
#define	N_LENG	0xfe	/* second stab entry with length information */


#endif // STUFF_H

