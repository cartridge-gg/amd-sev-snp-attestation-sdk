mod certs;
mod cpu;
mod kds;
mod utils;
mod verifier;

pub mod device;
pub mod error;
pub mod report;

// Re-Export SNP CertType from coco_provider
pub use coco_provider::coco::snp::types::CertType;

use certs::{Certificate, CertificateChain};
use device::{DerivedKeyOptions, Device, ReportOptions};
use kds::KDS;
use report::AttestationReport;
use std::collections::HashMap;

use crate::error::{Result, SevSnpError};

/// Indicate whether attestation verification should happen with
/// certs retrieved from SEV-SNP device or KDS or custom.
#[derive(PartialEq)]
pub enum AttestationFlow {
    /// Regular attestation flow, using certs from KDS
    /// This is the default flow.
    /// When attestation report is signed with VCEK, no certs need to be provided as they can be retrieved from KDS.
    /// When the attestation report is signed with VLEK, the VLEK cert must be provided.
    /// The ARK and ASK certs are retrieved from KDS.
    Regular,
    /// Extended attestation flow, using certs from SEV-SNP device
    /// When attestation report is signed with VCEK, all certs can be retrieved from the device.
    /// When the attestation report is signed with VLEK, only the VLEK cert can be retrieved from the device.
    /// The ARK and ASK certs are retrieved from KDS.
    Extended,
}

pub struct SevSnp {
    kds: KDS,
}

impl SevSnp {
    pub fn new() -> Result<Self> {
        let kds = KDS::new();
        Ok(SevSnp { kds })
    }

    /// Generate Derived Key using the default settings.
    ///
    /// Returns:
    /// - Ok: Derived Key as [u8;32]
    /// - Error: Problems with key generation
    pub fn get_derived_key(&self) -> Result<[u8; 32]> {
        let device = Device::new()?;
        let options = DerivedKeyOptions::default();
        device.get_derived_key(&options)
    }

    /// Generate Derived Key, but specify custom options for the key generation.
    /// When in doubt, use the default generator `get_derived_key()` instead of this.
    ///
    /// Returns:
    /// - Ok: Derived Key as [u8;32]
    /// - Error: Problems with key generation
    pub fn get_derived_key_with_options(&self, options: &DerivedKeyOptions) -> Result<[u8; 32]> {
        let device = Device::new()?;
        device.get_derived_key(&options)
    }

    /// Get the attestation report using the default settings.
    ///
    /// Returns:
    /// - A tuple containing the attestation report and the optional var data.
    /// - The attestation report is a `AttestationReport` struct.
    /// - The var data is an optional `Vec<u8>` containing the var data.
    /// Var data is only available if the device resides on an Azure Confidential VM.
    /// Var data provided by Azure can be used to verify the contents of the attestation report's report_data
    pub fn get_attestation_report(&self) -> Result<(AttestationReport, Option<Vec<u8>>)> {
        let device = Device::new()?;
        let options = ReportOptions::default();
        device.get_attestation_report(&options)
    }

    /// Get the attestation report, but specify custom options for the device.
    /// When in doubt, use the default `get_attestation_report()` instead of this.
    pub fn get_attestation_report_with_options(
        &self,
        options: &ReportOptions,
    ) -> Result<(AttestationReport, Option<Vec<u8>>)> {
        let device = Device::new()?;
        device.get_attestation_report(&options)
    }

    /// Retrieve certificates from the SevSnp device.
    /// This will only work if executed on an SEV-SNP machine (specifically, the VM is enlightened to SEV-SNP extensions)
    /// It will fail otherwise.
    /// Please also make sure to get certificates from the same device that generated the attestation report.
    /// Furthermore, if the signer is a VLEK, make sure to use this, as the KDS does not provide VLEK certs.
    ///
    /// # Returns:
    /// - Ok: HashMap containing the DER certificates
    /// - Error: Problems with certificate retrieval
    /// The HashMap will contain the following keys:
    /// - "ARK": AMD Root Key
    /// - "ASK": AMD Signing Key
    /// - One of "VCEK" or "VLEK": VCEK or VLEK certificate
    pub fn get_certificates_from_device(&self) -> Result<HashMap<String, Vec<u8>>> {
        let device = Device::new()?;
        device.get_certificates_der()
    }

    /// Retrieve certificates from KDS.
    /// This can be used outside of an SEV-SNP machine, but attestation report must be provided.
    /// If the signer of the attestation report is a VLEK, the retrieved certs will NOT contain the VLEK cert.
    /// This is because the VLEK cert is not available from KDS.
    ///
    /// # Returns:
    /// - Ok: HashMap containing the DER certificates
    /// - Error: Problems with certificate retrieval
    /// The HashMap will contain the following keys:
    /// - "ARK": AMD Root Key
    /// - "ASK": AMD Signing Key
    /// - "VCEK": VCEK certificate (only if the signer of the attestation report is VCEK)
    pub fn get_certificates_from_kds(
        &self,
        report: &AttestationReport,
    ) -> Result<HashMap<String, Vec<u8>>> {
        let signer_type = report.signing_key_type()?; // VLEK or VCEK
        let processor_model = report.get_cpu_codename()?;
        if signer_type == &CertType::VLEK {
            let ca = self.kds.fetch_ca_der(processor_model, CertType::VLEK)?;
            let mut cert_map = HashMap::<String, Vec<u8>>::new();
            cert_map.insert("ARK".to_string(), ca[1].clone());
            cert_map.insert("ASK".to_string(), ca[0].clone());
            return Ok(cert_map);
        }
        let ca = self.kds.fetch_ca_der(processor_model, CertType::VCEK)?;
        let vcek = self.kds.fetch_vcek_der(processor_model, report)?;
        let mut cert_map = HashMap::<String, Vec<u8>>::new();
        cert_map.insert("ARK".to_string(), ca[1].clone());
        cert_map.insert("ASK".to_string(), ca[0].clone());
        cert_map.insert("VCEK".to_string(), vcek);
        return Ok(cert_map);
    }

    /// Verify the chain of trust for the attestation report using the default settings.
    pub fn verify_attestation_report(
        &self,
        report: &AttestationReport,
        vlek_cert_der: Option<Vec<u8>>,
    ) -> Result<()> {
        let signer_type = report.signing_key_type()?;
        self.common_attestation_flow(
            report,
            signer_type,
            &AttestationFlow::Regular,
            vlek_cert_der,
        )
    }

    /// Verify the attestation report, but specify custom options for attestation flow.
    /// When in doubt, use the default `verify_attestation_report()` instead of this.
    pub fn verify_attestation_report_with_options(
        &self,
        report: &AttestationReport,
        flow: &AttestationFlow,
        vlek_cert_der: Option<Vec<u8>>,
    ) -> Result<()> {
        let signer_type = report.signing_key_type()?;
        self.common_attestation_flow(report, signer_type, flow, vlek_cert_der)
    }

    /// Common base for all attestation verification
    fn common_attestation_flow(
        &self,
        report: &AttestationReport,
        signer_type: &CertType,
        flow: &AttestationFlow,
        vlek_cert_der: Option<Vec<u8>>,
    ) -> Result<()> {
        let processor_model = report.get_cpu_codename()?;
        match flow {
            AttestationFlow::Regular => {
                self.regular_attestation_workflow(
                    &report,
                    signer_type,
                    processor_model,
                    vlek_cert_der,
                )?;
            }
            AttestationFlow::Extended => {
                // This verification method requires access to the hw device itself, and cannot be used in a remote attestation scenario.
                let device = Device::new()?;
                // Device options does not matter when only retrieving certs from it.
                let cert_map = device.get_certificates()?;
                self.extended_attestation_workflow(
                    &report,
                    signer_type,
                    processor_model,
                    &cert_map,
                )?;
            }
        }
        Ok(())
    }

    /// In the Extended Attestation workflow, the required certificates used to verify the attestation report are
    /// fetched from the AMD SEV-SNP machine's hw device.
    /// This means that this workflow cannot be run outside an AMD SEV-SNP machine.
    /// Note that when the signer is a VLEK, only the VLEK certificate is available from the device.
    /// So the ARK and ASK certificates need to be fetched from the AMD Key Distribution Service (KDS).
    fn extended_attestation_workflow(
        &self,
        report: &AttestationReport,
        signer_type: &CertType,
        processor_model: &cpu::ProcType,
        cert_map: &HashMap<String, Certificate>,
    ) -> Result<()> {
        let cert_chain = match signer_type {
            CertType::VLEK => self
                .kds
                .fetch_vlek_cert_chain(processor_model, cert_map.get("VLEK").unwrap())?,
            CertType::VCEK => CertificateChain::new(
                cert_map.get("ARK").unwrap().clone(),
                cert_map.get("ASK").unwrap().clone(),
                cert_map.get("VCEK").unwrap().clone(),
            ),
            _ => {
                return Err(SevSnpError::Firmware(
                    "Invalid signer found for Extended Attestation Workflow!".to_string(),
                ))
            }
        };

        let verifier = verifier::Verifier::new(&cert_chain, &report);
        verifier.verify()
    }

    /// In the Regular Attestation workflow, the certificates used to verify the attestation report are
    /// fetched from the AMD Key Distribution Service (KDS).
    /// When CertType is VCEK: all certs (VCEK, ARK, ASK) are fetched from KDS.
    /// When CertType is VLEK: VLEK cert must be provided as it cannot be queried from the KDS.
    ///                  ARK and ASK are then fetched from the KDS.
    fn regular_attestation_workflow(
        &self,
        report: &AttestationReport,
        signer_type: &CertType,
        processor_model: &cpu::ProcType,
        vlek_cert_der: Option<Vec<u8>>,
    ) -> Result<()> {
        let cert_chain = match signer_type {
            CertType::VLEK => {
                if vlek_cert_der.is_none() {
                    return Err(SevSnpError::Firmware(
                        "VLEK cert must be provided for regular attestation workflow!".to_string(),
                    ));
                }
                let vlek_cert = Certificate::from_der(&vlek_cert_der.unwrap())?;
                self.kds
                    .fetch_vlek_cert_chain(processor_model, &vlek_cert)?
            }
            CertType::VCEK => self.kds.fetch_vcek_cert_chain(processor_model, report)?,
            _ => {
                return Err(SevSnpError::Firmware(
                    "Invalid signer found for Regular Attestation Workflow!".to_string(),
                ))
            }
        };

        let verifier = verifier::Verifier::new(&cert_chain, &report);
        verifier.verify()
    }
}

#[cfg(feature = "clib")]
pub mod c {
    use crate::device::ReportOptions;

    use super::SevSnp;
    use std::ptr::copy_nonoverlapping;
    use std::sync::{LazyLock, Mutex};

    pub const SEV_SNP_OK: i32 = 0;
    pub const SEV_SNP_ERR_NULL_POINTER: i32 = -1;
    pub const SEV_SNP_ERR_BUFFER_TOO_SMALL: i32 = -2;
    pub const SEV_SNP_ERR_NO_REPORT: i32 = -3;
    pub const SEV_SNP_ERR_ATTESTATION_FAILED: i32 = -4;
    pub const SEV_SNP_ERR_LOCK_POISONED: i32 = -5;

    static ATTESTATION_REPORT: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));
    static VEK_CERT: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));
    static VAR_DATA: LazyLock<Mutex<Vec<u8>>> = LazyLock::new(|| Mutex::new(Vec::new()));

    /// Generate the attestation report.
    /// Returns the size of the report (positive) on success, or a negative error code on failure.
    /// Use the returned size to malloc a buffer before calling get_attestation_report_raw().
    #[unsafe(no_mangle)]
    pub extern "C" fn generate_attestation_report() -> i32 {
        let sev_snp = match SevSnp::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sev-snp: failed to initialize: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let (report, var_data) = match sev_snp.get_attestation_report() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("sev-snp: failed to get attestation report: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let bytes = match bincode::serialize(&report) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sev-snp: failed to serialize report: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let report_len = bytes.len();

        match ATTESTATION_REPORT.lock() {
            Ok(mut t) => *t = bytes,
            Err(e) => {
                eprintln!("sev-snp: attestation report lock poisoned: {e}");
                return SEV_SNP_ERR_LOCK_POISONED;
            }
        }

        if let Some(vd) = var_data {
            if !vd.is_empty() {
                match VAR_DATA.lock() {
                    Ok(mut t) => *t = vd,
                    Err(e) => {
                        eprintln!("sev-snp: var data lock poisoned: {e}");
                        return SEV_SNP_ERR_LOCK_POISONED;
                    }
                }
            }
        }

        report_len as i32
    }

    /// Generate the attestation report with custom options.
    /// Returns the size of the report (positive) on success, or a negative error code on failure.
    /// `report_data` must point to a 64-byte buffer. Returns SEV_SNP_ERR_NULL_POINTER if null.
    #[unsafe(no_mangle)]
    pub extern "C" fn generate_attestation_report_with_options(
        report_data: *const u8,
        vmpl: u32,
    ) -> i32 {
        if report_data.is_null() {
            eprintln!("sev-snp: report_data is null");
            return SEV_SNP_ERR_NULL_POINTER;
        }
        let sev_snp = match SevSnp::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sev-snp: failed to initialize: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let mut rust_report_data: [u8; 64] = [0; 64];
        unsafe {
            copy_nonoverlapping(report_data, rust_report_data.as_mut_ptr(), 64);
        }
        let options = ReportOptions {
            report_data: Some(rust_report_data),
            vmpl: Some(vmpl),
        };
        let (report, var_data) = match sev_snp.get_attestation_report_with_options(&options) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("sev-snp: failed to get attestation report with options: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let bytes = match bincode::serialize(&report) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sev-snp: failed to serialize report: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let report_len = bytes.len();

        match ATTESTATION_REPORT.lock() {
            Ok(mut t) => *t = bytes,
            Err(e) => {
                eprintln!("sev-snp: attestation report lock poisoned: {e}");
                return SEV_SNP_ERR_LOCK_POISONED;
            }
        }

        if let Some(vd) = var_data {
            if !vd.is_empty() {
                match VAR_DATA.lock() {
                    Ok(mut t) => *t = vd,
                    Err(e) => {
                        eprintln!("sev-snp: var data lock poisoned: {e}");
                        return SEV_SNP_ERR_LOCK_POISONED;
                    }
                }
            }
        }

        report_len as i32
    }

    /// Copy the attestation report into `buf`.
    /// `buf_len` must be at least the size returned by generate_attestation_report().
    /// Returns bytes written on success, or a negative error code on failure.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_attestation_report_raw(buf: *mut u8, buf_len: usize) -> i32 {
        if buf.is_null() {
            eprintln!("sev-snp: get_attestation_report_raw: buf is null");
            return SEV_SNP_ERR_NULL_POINTER;
        }
        let bytes = match ATTESTATION_REPORT.lock() {
            Ok(t) => t.clone(),
            Err(e) => {
                eprintln!("sev-snp: attestation report lock poisoned: {e}");
                return SEV_SNP_ERR_LOCK_POISONED;
            }
        };
        if bytes.is_empty() {
            eprintln!("sev-snp: no attestation report found, call generate_attestation_report() first");
            return SEV_SNP_ERR_NO_REPORT;
        }
        if buf_len < bytes.len() {
            eprintln!("sev-snp: buffer too small ({buf_len} < {})", bytes.len());
            return SEV_SNP_ERR_BUFFER_TOO_SMALL;
        }
        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        }
        bytes.len() as i32
    }

    /// Generate the VEK certificate.
    /// Returns the size of the cert (positive) on success, or a negative error code on failure.
    #[unsafe(no_mangle)]
    pub extern "C" fn generate_vek_cert() -> i32 {
        let sev_snp = match SevSnp::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sev-snp: failed to initialize: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let cert_map = match sev_snp.get_certificates_from_device() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("sev-snp: failed to get certificates from device: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let vek_cert = if let Some(cert) = cert_map.get("VLEK") {
            cert
        } else if let Some(cert) = cert_map.get("VCEK") {
            cert
        } else {
            eprintln!("sev-snp: no VLEK or VCEK certificate found");
            return SEV_SNP_ERR_ATTESTATION_FAILED;
        };
        let len = vek_cert.len();
        match VEK_CERT.lock() {
            Ok(mut t) => *t = vek_cert.to_vec(),
            Err(e) => {
                eprintln!("sev-snp: vek cert lock poisoned: {e}");
                return SEV_SNP_ERR_LOCK_POISONED;
            }
        }
        len as i32
    }

    /// Copy the VEK certificate into `buf`.
    /// `buf_len` must be at least the size returned by generate_vek_cert().
    /// Returns bytes written on success, or a negative error code on failure.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_vek_cert(buf: *mut u8, buf_len: usize) -> i32 {
        if buf.is_null() {
            eprintln!("sev-snp: get_vek_cert: buf is null");
            return SEV_SNP_ERR_NULL_POINTER;
        }
        let bytes = match VEK_CERT.lock() {
            Ok(t) => t.clone(),
            Err(e) => {
                eprintln!("sev-snp: vek cert lock poisoned: {e}");
                return SEV_SNP_ERR_LOCK_POISONED;
            }
        };
        if bytes.is_empty() {
            eprintln!("sev-snp: no VEK cert found, call generate_vek_cert() first");
            return SEV_SNP_ERR_NO_REPORT;
        }
        if buf_len < bytes.len() {
            eprintln!("sev-snp: buffer too small ({buf_len} < {})", bytes.len());
            return SEV_SNP_ERR_BUFFER_TOO_SMALL;
        }
        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        }
        bytes.len() as i32
    }

    /// Retrieve the length of var_data. Call after generate_attestation_report().
    /// Returns the length (non-negative) on success, or a negative error code on failure.
    /// Returns 0 if var_data is empty.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_var_data_len() -> i32 {
        match VAR_DATA.lock() {
            Ok(t) => t.len() as i32,
            Err(e) => {
                eprintln!("sev-snp: var data lock poisoned: {e}");
                SEV_SNP_ERR_LOCK_POISONED
            }
        }
    }

    /// Copy var_data into `buf`.
    /// `buf_len` must be at least the value returned by get_var_data_len().
    /// Returns bytes written on success, or a negative error code on failure.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_var_data(buf: *mut u8, buf_len: usize) -> i32 {
        if buf.is_null() {
            eprintln!("sev-snp: get_var_data: buf is null");
            return SEV_SNP_ERR_NULL_POINTER;
        }
        let bytes = match VAR_DATA.lock() {
            Ok(t) => t.clone(),
            Err(e) => {
                eprintln!("sev-snp: var data lock poisoned: {e}");
                return SEV_SNP_ERR_LOCK_POISONED;
            }
        };
        if bytes.is_empty() {
            eprintln!("sev-snp: no var data found, call generate_attestation_report() first");
            return SEV_SNP_ERR_NO_REPORT;
        }
        if buf_len < bytes.len() {
            eprintln!("sev-snp: buffer too small ({buf_len} < {})", bytes.len());
            return SEV_SNP_ERR_BUFFER_TOO_SMALL;
        }
        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        }
        bytes.len() as i32
    }

    /// Retrieve the report ID from a fresh attestation report.
    /// `buf` must point to a buffer of at least 32 bytes.
    /// Returns bytes written (32) on success, or a negative error code on failure.
    #[unsafe(no_mangle)]
    pub extern "C" fn get_report_id(buf: *mut u8, buf_len: usize) -> i32 {
        if buf.is_null() {
            eprintln!("sev-snp: get_report_id: buf is null");
            return SEV_SNP_ERR_NULL_POINTER;
        }
        let sev_snp = match SevSnp::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sev-snp: failed to initialize: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let (report, _) = match sev_snp.get_attestation_report() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("sev-snp: failed to get attestation report: {e}");
                return SEV_SNP_ERR_ATTESTATION_FAILED;
            }
        };
        let bytes = report.report_id;
        if buf_len < bytes.len() {
            eprintln!("sev-snp: buffer too small ({buf_len} < {}), need at least 32 bytes", bytes.len());
            return SEV_SNP_ERR_BUFFER_TOO_SMALL;
        }
        unsafe {
            copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        }
        bytes.len() as i32
    }
}
