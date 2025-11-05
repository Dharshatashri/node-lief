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
     */
    class Section {
      readonly name: string;
      readonly type: string;
      readonly virtualAddress: bigint;
      size: bigint;
      readonly fileOffset: bigint;
      virtualSize: bigint;
      content: number[] | Buffer;
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
    class Binary {
      constructor(filename: string);

      // Properties inherited from Abstract.Binary
      readonly format: 'ELF';
      readonly entrypoint: bigint;
      readonly isPie: boolean;
      readonly hasNx: boolean;
      readonly header: Abstract.Header;

      // Methods
      sections(): Abstract.Section[];
      symbols(): Abstract.Symbol[];
      relocations(): Abstract.Relocation[];
      getSymbol(name: string): Abstract.Symbol | null;
      patchAddress(address: bigint | number, patch: Buffer | number[]): void;
      write(outputPath: string): void;
    }
  }

  namespace PE {
    /**
     * PE (Windows Portable Executable) binary class
     * Used for Windows .exe and .dll manipulation
     */
    class Binary {
      constructor(filename: string);

      // Properties inherited from Abstract.Binary
      readonly format: 'PE';
      readonly entrypoint: bigint;
      readonly isPie: boolean;
      readonly hasNx: boolean;
      readonly header: Abstract.Header;

      // Methods
      sections(): Abstract.Section[];
      symbols(): Abstract.Symbol[];
      relocations(): Abstract.Relocation[];
      getSymbol(name: string): Abstract.Symbol | null;
      patchAddress(address: bigint | number, patch: Buffer | number[]): void;
      write(outputPath: string): void;
    }
  }

  namespace MachO {
    /**
     * Mach-O (macOS/iOS) binary class
     * Used for macOS executable manipulation
     */
    class Binary {
      constructor(filename: string);

      // Properties inherited from Abstract.Binary
      readonly format: 'MachO';
      readonly entrypoint: bigint;
      readonly isPie: boolean;
      readonly hasNx: boolean;

      // MachO-specific properties
      readonly hasCodeSignature: boolean;

      // Methods
      sections(): Abstract.Section[];
      symbols(): Abstract.Symbol[];
      getSegment(name: string): Segment | null;
      removeSignature(): void;
      extendSegment(segment: Segment, size: bigint | number): boolean;
      write(outputPath: string): void;
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
