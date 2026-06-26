//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils} from "../utils/BytesUtils.sol";

enum CertType {
    // Versioned Chip Endorsement Key
    VCEK,
    // Versioned Loaded Endorsement Key
    VLEK,
    // AMD SEV Signing Key
    ASK,
    // AMD Root Signing Key
    ARK
}

/// @notice TCB_VERSION structure can be found in Table 3 of the manual
/// @notice https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
struct TcbVersion {
    uint8 fmc;
    uint8 bootloader;
    uint8 tee;
    uint8 snp;
    uint8[3] reserved;
    uint8 microcode;
}

uint256 constant TCB_VERSION_SIZE = 8; // BYTES

// AttestationReport is split into ReportHeader (17 fields) + ReportFooter (16 fields)
// because alloy-sol-types only implements SolValue/SolTypeValue for tuples up to ~24
// elements; the flat 33-field struct fails to compile on alloy >= 1.4. The grouping
// preserves field order and is purely a Rust codegen concern — the on-chain journal
// carries the raw report bytes (decoded by offset), so no wire format changes.
struct ReportHeader {
    uint32 version;
    uint32 guestSvn;
    bytes8 guestPolicyRaw;
    bytes16 familyId;
    bytes16 imageId;
    uint32 vmpl;
    uint32 sigAlgo;
    TcbVersion currentTcb;
    bytes8 platInfoRaw;
    uint32 authorKeyEn;
    uint32 reserved0;
    bytes reportData; // 64 bytes
    bytes measurement; // 48 bytes
    bytes32 hostData;
    bytes idKeyDigest; // 48 bytes
    bytes authorKeyDigest; // 48 bytes
    bytes32 reportId;
}

struct ReportFooter {
    bytes32 reportIdMd;
    TcbVersion reportedTcb;
    bytes24 reserved1;
    bytes chipId; // 64 bytes
    TcbVersion committedTcb;
    uint8 currentBuild;
    uint8 currentMinor;
    uint8 currentMajor;
    uint8 reserved2;
    uint8 committedBuild;
    uint8 committedMinor;
    uint8 committedMajor;
    uint8 reserved3;
    TcbVersion launchTcb;
    bytes reserved_4; // 168 bytes
    bytes rawSignature;
}

struct AttestationReport {
    ReportHeader header;
    ReportFooter footer;
}

library TcbVersionLib {
    using BytesUtils for bytes;

    function parseTcbVersion(bytes memory rawTcb) internal pure returns (TcbVersion memory tcb) {
        uint8[3] memory reserved;
        for (uint256 i = 0; i < 3; i++) {
            reserved[i] = rawTcb.readUint8(4 + i);
        }
        
        tcb = TcbVersion({
            fmc: rawTcb.readUint8(0),
            bootloader: rawTcb.readUint8(1),
            tee: rawTcb.readUint8(2),
            snp: rawTcb.readUint8(3),
            reserved: reserved,
            microcode: rawTcb.readUint8(7)
        });
    }
}

library AttestationReportLib {
    using BytesUtils for bytes;

    /// @notice Attestation Report Serialization can be found in Table 23 of the manual
    /// @notice https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
    function deserializeRawAttestationReport(bytes memory attestatonReportRaw)
        internal
        pure
        returns (AttestationReport memory report)
    {
        // --- ReportHeader (0x00 .. 0x160) ---
        // 0x00: version (4 bytes)
        report.header.version = attestatonReportRaw.readUint32(0x00);
        // 0x04: guest_svn (4 bytes)
        report.header.guestSvn = attestatonReportRaw.readUint32(0x04);
        // 0x08: policy (8 bytes)
        report.header.guestPolicyRaw = bytes8(attestatonReportRaw.readBytesN(0x08, 8));
        // 0x10: family_id (16 bytes)
        report.header.familyId = bytes16(attestatonReportRaw.readBytesN(0x10, 16));
        // 0x20: image_id (16 bytes)
        report.header.imageId = bytes16(attestatonReportRaw.readBytesN(0x20, 16));
        // 0x30: vmpl (4 bytes)
        report.header.vmpl = attestatonReportRaw.readUint32(0x30);
        // 0x34: sig_algo (4 bytes)
        report.header.sigAlgo = attestatonReportRaw.readUint32(0x34);
        // 0x38: current_tcb (8 bytes)
        report.header.currentTcb = TcbVersionLib.parseTcbVersion(attestatonReportRaw.substring(0x38, TCB_VERSION_SIZE));
        // 0x40: platform_info (8 bytes)
        report.header.platInfoRaw = bytes8(attestatonReportRaw.readBytesN(0x40, 8));
        // 0x48: author_key_en (4 bytes)
        report.header.authorKeyEn = attestatonReportRaw.readUint32(0x48);
        // 0x4C: reserved0 (4 bytes)
        report.header.reserved0 = attestatonReportRaw.readUint32(0x4C);
        // 0x50: report_data (64 bytes)
        report.header.reportData = attestatonReportRaw.substring(0x50, 64);
        // 0x90: measurement (48 bytes)
        report.header.measurement = attestatonReportRaw.substring(0x90, 48);
        // 0xC0: host_data (32 bytes)
        report.header.hostData = attestatonReportRaw.readBytes32(0xC0);
        // 0xE0: id_key_digest (48 bytes)
        report.header.idKeyDigest = attestatonReportRaw.substring(0xE0, 48);
        // 0x110: author_key_digest (48 bytes)
        report.header.authorKeyDigest = attestatonReportRaw.substring(0x110, 48);
        // 0x140: report_id (32 bytes)
        report.header.reportId = attestatonReportRaw.readBytes32(0x140);

        // --- ReportFooter (0x160 .. end) ---
        // 0x160: report_id_ma (32 bytes)
        report.footer.reportIdMd = attestatonReportRaw.readBytes32(0x160);
        // 0x180: reported_tcb (8 bytes)
        report.footer.reportedTcb = TcbVersionLib.parseTcbVersion(attestatonReportRaw.substring(0x180, TCB_VERSION_SIZE));
        // 0x188: reserved1 (24 bytes)
        report.footer.reserved1 = bytes24(attestatonReportRaw.readBytesN(0x188, 24));
        // 0x1A0: chip_id (64 bytes)
        report.footer.chipId = attestatonReportRaw.substring(0x1A0, 64);
        // 0x1E0: committed_tcb (8 bytes)
        report.footer.committedTcb = TcbVersionLib.parseTcbVersion(attestatonReportRaw.substring(0x1E0, TCB_VERSION_SIZE));
        // 0x1E8: current_build (1 byte)
        report.footer.currentBuild = attestatonReportRaw.readUint8(0x1E8);
        // 0x1E9: current_minor (1 byte)
        report.footer.currentMinor = attestatonReportRaw.readUint8(0x1E9);
        // 0x1EA: current_major (1 byte)
        report.footer.currentMajor = attestatonReportRaw.readUint8(0x1EA);
        // 0x1EB: reserved2 (1 byte)
        report.footer.reserved2 = attestatonReportRaw.readUint8(0x1EB);
        // 0x1EC: committed_build (1 byte)
        report.footer.committedBuild = attestatonReportRaw.readUint8(0x1EC);
        // 0x1ED: committed_minor (1 byte)
        report.footer.committedMinor = attestatonReportRaw.readUint8(0x1ED);
        // 0x1EE: committed_major (1 byte)
        report.footer.committedMajor = attestatonReportRaw.readUint8(0x1EE);
        // 0x1EF: reserved3 (1 byte)
        report.footer.reserved3 = attestatonReportRaw.readUint8(0x1EF);
        // 0x1F0: launch_tcb (8 bytes)
        report.footer.launchTcb = TcbVersionLib.parseTcbVersion(attestatonReportRaw.substring(0x1F0, TCB_VERSION_SIZE));
        // 0x1F8: reserved4 (168 bytes)
        report.footer.reserved_4 = attestatonReportRaw.substring(0x1F8, 168);
        // 0x2A0: signature (512 bytes)
        report.footer.rawSignature = attestatonReportRaw.substring(0x2A0, 512);
    }

    /// @notice extract the reported tcb values from the report without parsing the entire data
    function getReportedTcb(bytes memory attestationReportRaw) internal pure returns (TcbVersion memory reportedTcb) {
        uint256 offset = 0x0180;
        reportedTcb = TcbVersionLib.parseTcbVersion(attestationReportRaw.substring(offset, TCB_VERSION_SIZE));
    }

    /// @notice determine the signing VEK type from the report without parsing the entire data
    function getVEKType(bytes memory attestationReportRaw) internal pure returns (CertType vekType) {
        uint256 offset = 0x48;
        bytes4 author_key_en = bytes4(attestationReportRaw.substring(offset, 4));
        bytes1 bits = author_key_en[0];
        bytes1 signerType = bits & 0x1c;
        if (signerType == 0x0) {
            vekType = CertType.VCEK;
        } else if (signerType == 0x04) {
            vekType = CertType.VLEK;
        } else {
            revert("Unknown VEK type");
        }
    }
}
