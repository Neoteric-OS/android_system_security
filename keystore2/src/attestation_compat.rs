// SPDX-FileCopyrightText: 2026 kenway214
// SPDX-License-Identifier: Apache-2.0

use crate::utils::AppUid;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Certificate::Certificate, KeyCharacteristics::KeyCharacteristics,
    KeyCreationResult::KeyCreationResult, KeyOrigin::KeyOrigin, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use keystore2_crypto::{generate_software_attested_key, software_root_cert_der};
use log::{info, warn};

const BLOB_MARKER: &[u8] = b"KMCPTkey\x00";

pub(crate) fn is_simulated_blob(blob: &[u8]) -> bool {
    blob.starts_with(BLOB_MARKER)
}

pub(crate) fn strip_simulated_blob(blob: &[u8]) -> &[u8] {
    if blob.starts_with(BLOB_MARKER) {
        &blob[BLOB_MARKER.len()..]
    } else {
        blob
    }
}

pub(crate) fn generate_software_key_for_uid(
    caller_uid: AppUid,
    creation_params: &[KeyParameter],
) -> Option<KeyCreationResult> {
    let requested_algo =
        creation_params.iter().find(|p| p.tag == Tag::ALGORITHM).and_then(|p| match p.value {
            KeyParameterValue::Algorithm(Algorithm::RSA) => Some("rsa"),
            KeyParameterValue::Algorithm(Algorithm::EC) => Some("ec"),
            _ => None,
        })?;

    let key_type = if requested_algo == "rsa" { 1 } else { 2 };
    let rsa_size = creation_params
        .iter()
        .find(|p| p.tag == Tag::KEY_SIZE)
        .and_then(|p| match p.value {
            KeyParameterValue::Integer(s) => Some(s),
            _ => None,
        })
        .unwrap_or(2048);
    let challenge = creation_params
        .iter()
        .find(|p| p.tag == Tag::ATTESTATION_CHALLENGE)
        .and_then(|p| match &p.value {
            KeyParameterValue::Blob(b) => Some(b.as_slice()),
            _ => None,
        })
        .unwrap_or(b"attest_challenge");

    let is_attest_key = creation_params.iter().any(|p| {
        p.tag == Tag::PURPOSE
            && matches!(p.value, KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY))
    });

    let attest_app_id = creation_params
        .iter()
        .find(|p| p.tag == Tag::ATTESTATION_APPLICATION_ID)
        .and_then(|p| match &p.value {
            KeyParameterValue::Blob(b) => Some(b.as_slice()),
            _ => None,
        })
        .unwrap_or(&[]);

    match generate_software_attested_key(
        key_type,
        rsa_size,
        challenge,
        attest_app_id,
        is_attest_key,
    ) {
        Ok((privkey, cert)) => {
            let mut marked_blob = Vec::with_capacity(BLOB_MARKER.len() + privkey.len());
            marked_blob.extend_from_slice(BLOB_MARKER);
            marked_blob.extend(privkey);

            let mut full_chain = vec![Certificate { encodedCertificate: cert }];
            if let Ok(root_der) = software_root_cert_der() {
                full_chain.push(Certificate { encodedCertificate: root_der });
            }

            info!(
                "Generated software key for uid={:?}, alg={}, is_attest_key={}",
                caller_uid, requested_algo, is_attest_key
            );

            let mut km_authorizations = Vec::new();
            for p in creation_params {
                if p.tag != Tag::ATTESTATION_CHALLENGE
                    && p.tag != Tag::ATTESTATION_APPLICATION_ID
                    && p.tag != Tag::CERTIFICATE_SUBJECT
                {
                    km_authorizations.push(p.clone());
                }
            }
            km_authorizations.push(KeyParameter {
                tag: Tag::ORIGIN,
                value: KeyParameterValue::Origin(KeyOrigin::GENERATED),
            });

            let key_characteristics = vec![KeyCharacteristics {
                securityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
                authorizations: km_authorizations,
            }];

            Some(KeyCreationResult {
                keyBlob: marked_blob,
                keyCharacteristics: key_characteristics,
                certificateChain: full_chain,
            })
        }
        Err(e) => {
            warn!("Software key generation failed: {:?}", e);
            None
        }
    }
}
