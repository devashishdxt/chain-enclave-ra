/// Enclave request
pub enum EnclaveRequest {
    /// Request enclave to generate enclave report
    GetEnclaveReport { target_info: Vec<u8> },
    /// Request enclave to verify QE report
    VerifyQeReport { qe_report: Vec<u8> },
}

/// Response from enclave
pub enum EnclaveResponse {
    /// Response received from enclave with enclave report
    ///
    /// # Note
    ///
    /// These bytes can be converted into `sgx_isa::Report` using `Report::try_copy_from()`
    GetEnclaveReport { report: Vec<u8> },
    /// Response received from enclave
    ///
    /// # Note
    ///
    /// If verification of QE report fails, this returns a string with error message
    VerifyQeReport { result: Result<(), String> },
}
