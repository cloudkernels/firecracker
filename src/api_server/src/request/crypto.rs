use super::super::VmmAction;
use parsed_request::{checked_id, Error, ParsedRequest};
use request::{Body, StatusCode};
use vmm::vmm_config::crypto::CryptoDeviceConfig;

pub fn parse_put_crypto(body: &Body, id_from_path: Option<&&str>) -> Result<ParsedRequest, Error> {
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        return Err(Error::EmptyID);
    };

    let crypto_cfg = serde_json::from_slice::<CryptoDeviceConfig>(body.raw()).map_err(|e| {
        Error::SerdeJson(e)
    })?;

    if id != crypto_cfg.crypto_dev_id {
        Err(Error::Generic(
                StatusCode::BadRequest,
                "The id from the path does not match the id from the body!".to_string(),
        ))
    } else {
        Ok(ParsedRequest::new_sync(VmmAction::InsertCryptoDevice(crypto_cfg)))
    }
}
