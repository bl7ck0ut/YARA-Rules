import "pe"
import "math"

rule Suspicious_Rich_Header {
    meta:
        author = "Bhavesh Lohar"
        description = "Detects abnormally large PE DOS stubs indicating potential Rich Header payload injection or padding."
        date = "2026-02-24"
        reference = "Hunting for Decoupled Loaders and PE Structural Anomalies"

    condition:
        // Verify the file is a valid Windows Executable (MZ magic bytes)
        uint16(0) == 0x5a4d 
        
        and 
        
        /* Check the e_lfanew pointer at offset 0x3C. If it is greater than 0x150 (336 bytes), the padding has been artificially expanded. */
        uint32(0x3c) > 0x150 
        
        and 
        
        /* Ensure the file actually has a "Rich" signature. */
        for any i in (0x40 .. uint32(0x3c)): (
            uint32(i) == 0x68636952
        )
}