//! GeoIP lookup service

use crate::error::Result;
use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// GeoIP lookup result
#[derive(Debug, Clone, Default)]
pub struct GeoIpInfo {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub continent_code: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

/// GeoIP service for IP lookups
pub struct GeoIpService {
    city_reader: Option<Arc<Reader<Vec<u8>>>>,
    asn_reader: Option<Arc<Reader<Vec<u8>>>>,
}

impl GeoIpService {
    /// Create a new GeoIP service
    pub fn new<P: AsRef<Path>>(city_db_path: Option<P>, asn_db_path: Option<P>) -> Result<Self> {
        let city_reader = if let Some(path) = city_db_path {
            match Reader::open_readfile(path.as_ref()) {
                Ok(reader) => {
                    info!("GeoIP city database loaded");
                    Some(Arc::new(reader))
                }
                Err(e) => {
                    warn!("Failed to load GeoIP city database: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let asn_reader = if let Some(path) = asn_db_path {
            match Reader::open_readfile(path.as_ref()) {
                Ok(reader) => {
                    info!("GeoIP ASN database loaded");
                    Some(Arc::new(reader))
                }
                Err(e) => {
                    warn!("Failed to load GeoIP ASN database: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            city_reader,
            asn_reader,
        })
    }

    /// Create a dummy service (for testing or when GeoIP is not available)
    pub fn dummy() -> Self {
        Self {
            city_reader: None,
            asn_reader: None,
        }
    }

    /// Look up an IP address
    pub fn lookup(&self, ip: IpAddr) -> GeoIpInfo {
        let mut info = GeoIpInfo::default();

        // City/Country lookup
        if let Some(ref reader) = self.city_reader {
            if let Ok(city) = reader.lookup::<geoip2::City>(ip) {
                if let Some(country) = city.country {
                    info.country_code = country.iso_code.map(|s| s.to_string());
                    info.country_name = country
                        .names
                        .and_then(|n| n.get("en").map(|s| s.to_string()));
                }

                if let Some(continent) = city.continent {
                    info.continent_code = continent.code.map(|s| s.to_string());
                }

                if let Some(c) = city.city {
                    info.city = c.names.and_then(|n| n.get("en").map(|s| s.to_string()));
                }

                if let Some(location) = city.location {
                    info.latitude = location.latitude;
                    info.longitude = location.longitude;
                }
            }
        }

        // ASN lookup
        if let Some(ref reader) = self.asn_reader {
            if let Ok(asn) = reader.lookup::<geoip2::Asn>(ip) {
                info.asn = asn.autonomous_system_number;
                info.as_org = asn.autonomous_system_organization.map(|s| s.to_string());
            }
        }

        info
    }

    /// Check if an IP is from a specific country
    pub fn is_country(&self, ip: IpAddr, country_code: &str) -> bool {
        let info = self.lookup(ip);
        info.country_code
            .map(|c| c.eq_ignore_ascii_case(country_code))
            .unwrap_or(false)
    }

    /// Check if an IP is from any of the specified countries
    pub fn is_any_country(&self, ip: IpAddr, country_codes: &[&str]) -> bool {
        let info = self.lookup(ip);
        if let Some(code) = info.country_code {
            country_codes.iter().any(|c| c.eq_ignore_ascii_case(&code))
        } else {
            false
        }
    }

    /// Check if databases are loaded
    pub fn is_available(&self) -> bool {
        self.city_reader.is_some() || self.asn_reader.is_some()
    }
}

/// Country code to ID mapping for efficient eBPF map storage
pub fn country_code_to_id(code: &str) -> Option<u16> {
    // ISO 3166-1 alpha-2 codes mapped to numeric IDs
    // This is a subset - full implementation would have all countries
    match code.to_uppercase().as_str() {
        "US" => Some(1),
        "CA" => Some(2),
        "GB" => Some(3),
        "DE" => Some(4),
        "FR" => Some(5),
        "NL" => Some(6),
        "AU" => Some(7),
        "JP" => Some(8),
        "KR" => Some(9),
        "SG" => Some(10),
        "BR" => Some(11),
        "IN" => Some(12),
        "RU" => Some(13),
        "CN" => Some(14),
        "HK" => Some(15),
        "TW" => Some(16),
        "VN" => Some(17),
        "ID" => Some(18),
        "TH" => Some(19),
        "PH" => Some(20),
        // Add more as needed...
        _ => None,
    }
}

/// ID to country code mapping
pub fn id_to_country_code(id: u16) -> Option<&'static str> {
    match id {
        1 => Some("US"),
        2 => Some("CA"),
        3 => Some("GB"),
        4 => Some("DE"),
        5 => Some("FR"),
        6 => Some("NL"),
        7 => Some("AU"),
        8 => Some("JP"),
        9 => Some("KR"),
        10 => Some("SG"),
        11 => Some("BR"),
        12 => Some("IN"),
        13 => Some("RU"),
        14 => Some("CN"),
        15 => Some("HK"),
        16 => Some("TW"),
        17 => Some("VN"),
        18 => Some("ID"),
        19 => Some("TH"),
        20 => Some("PH"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_country_code_mapping() {
        assert_eq!(country_code_to_id("US"), Some(1));
        assert_eq!(country_code_to_id("us"), Some(1));
        assert_eq!(id_to_country_code(1), Some("US"));
        assert_eq!(country_code_to_id("XX"), None);
    }

    #[test]
    fn test_dummy_service() {
        let service = GeoIpService::dummy();
        assert!(!service.is_available());

        let info = service.lookup("8.8.8.8".parse().unwrap());
        assert!(info.country_code.is_none());
    }
}
