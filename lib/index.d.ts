/**
 * LIEF Node.js Bindings - TypeScript Definitions
 *
 * Provides TypeScript support for LIEF binary parsing and manipulation.
 * Supports ELF, PE, Mach-O, and other executable formats.
 */

declare namespace LIEF {
  namespace Abstract {
    /**
     * Generic binary executable interface
     * Works with ELF, PE, Mach-O, and other formats
     */
    class Binary {
      constructor(filename: string);

      // Properties
      readonly format: 'ELF' | 'PE' | 'MachO' | 'UNKNOWN';
      readonly entrypoint: bigint;
      readonly isPie: boolean;
      readonly hasNx: boolean;
      readonly header: Header;

      // Methods
      sections(): Section[];
      symbols(): Symbol[];
      relocations(): Relocation[];
      segments(): any[]; // Empty array - format-specific binaries should override
      getSymbol(name: string): Symbol | null;
      patchAddress(address: bigint | number, patch: Buffer | number[]): void;
      write(outputPath: string): void;
    }

    interface Header {
      architecture: number;
      entrypoint: bigint;
      is_32: boolean;
      is_64: boolean;
    }

    /**
     * Represents a section in a binary
     * Provides read/write access to section properties and content
     *
     * Note: For PE-specific sections with virtualSize support, use PE.Section.
     */
    class Section {
      readonly name: string;
      readonly type: string;
      readonly virtualAddress: bigint;
      size: bigint;
      readonly fileOffset: bigint;
      /**
       * Section content as a Buffer.
       * Getter returns Buffer. Setter accepts Buffer or number[].
       */
      get content(): Buffer;
      set content(value: Buffer | number[]);
      readonly offset: bigint;
    }

    interface Symbol {
      name: string;
      value: bigint;
      size: bigint;
    }

    interface Relocation {
      address: bigint;
      size: number;
    }
  }

  namespace ELF {
    /**
     * ELF-specific binary class
     * Used for Linux/Unix executable manipulation
     */
    class Binary extends Abstract.Binary {
      constructor(filename: string);

      // Override format type
      readonly format: 'ELF';
    }
  }

  namespace PE {
    /**
     * PE-specific section class
     * Provides proper virtualSize support and PE-specific properties
     */
    class Section extends Abstract.Section {
      // PE sections have proper virtual_size support (not just an alias for size)
      virtualSize: bigint;

      // PE-specific properties
      readonly characteristics: number;
    }

    /**
     * PE (Windows Portable Executable) binary class
     * Used for Windows .exe and .dll manipulation
     */
    class Binary extends Abstract.Binary {
      constructor(filename: string);

      // Override format type
      readonly format: 'PE';

      // PE-specific properties
      readonly optionalHeader: OptionalHeader;

      // Override to return PE-specific sections
      sections(): Section[];

      // PE-specific methods
      getSection(name: string): Section | null;
    }

    /**
     * PE Optional Header
     * Contains critical PE file metadata (despite the name, it's mandatory for PE files)
     */
    class OptionalHeader {
      readonly magic: 'PE32' | 'PE32_PLUS' | 'UNKNOWN';
      readonly majorLinkerVersion: number;
      readonly minorLinkerVersion: number;
      readonly sizeOfCode: number;
      readonly sizeOfInitializedData: number;
      readonly sizeOfUninitializedData: number;
      readonly addressOfEntrypoint: number;
      readonly baseOfCode: number;
      readonly baseOfData: number;
      readonly imagebase: bigint;
      readonly sectionAlignment: number;
      readonly fileAlignment: number;
      readonly majorOperatingSystemVersion: number;
      readonly minorOperatingSystemVersion: number;
      readonly majorImageVersion: number;
      readonly minorImageVersion: number;
      readonly majorSubsystemVersion: number;
      readonly minorSubsystemVersion: number;
      readonly win32VersionValue: number;
      readonly sizeOfImage: number;
      readonly sizeOfHeaders: number;
      readonly checksum: number;
      readonly subsystem: number;
      readonly dllCharacteristics: number;
      readonly sizeOfStackReserve: bigint;
      readonly sizeOfStackCommit: bigint;
      readonly sizeOfHeapReserve: bigint;
      readonly sizeOfHeapCommit: bigint;
    }
  }

  namespace MachO {
    /**
     * Mach-O (macOS/iOS) binary class
     * Used for macOS executable manipulation
     */
    class Binary extends Abstract.Binary {
      constructor(filename: string);

      // Override format type
      readonly format: 'MachO';

      // MachO-specific properties
      readonly hasCodeSignature: boolean;

      // MachO-specific methods
      getSegment(name: string): Segment | null;
      removeSignature(): void;
      extendSegment(segment: Segment, size: bigint | number): boolean;
    }

    /**
     * Represents a MachO segment (SegmentCommand)
     */
    class Segment {
      readonly name: string;
      readonly type: string;
      readonly virtualAddress: bigint;
      readonly virtualSize: bigint;
      readonly fileOffset: bigint;
      readonly fileSize: bigint;

      sections(): Abstract.Section[];
      getSection(name: string): Abstract.Section | null;
    }

    /**
     * Represents a MachO Fat/Universal binary
     * Can contain multiple architectures
     */
    class FatBinary {
      size(): number;
      at(index: number): Binary | null;
      take(index: number): Binary | null;
    }

    /**
     * Parse a MachO binary file
     * @param filename - Path to the MachO binary file
     * @returns FatBinary object (may contain single or multiple architectures)
     */
    function parse(filename: string): FatBinary;
  }

  namespace logging {
    /**
     * Disable LIEF logging
     */
    function disable(): void;

    /**
     * Enable LIEF logging
     */
    function enable(): void;
  }

  /**
   * Parse a binary file and return format-specific binary object
   * @param filename - Path to the binary file
   * @returns Binary object (type depends on detected format: ELF.Binary, PE.Binary, MachO.Binary, or Abstract.Binary)
   */
  function parse(filename: string): Abstract.Binary | ELF.Binary | PE.Binary | MachO.Binary;
}

export = LIEF;
