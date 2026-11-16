//! The one kind of device the broker creates: a FIDO HID authenticator.

use hirz_sys::uhid::{BUS_USB, CreateParams};

/// HID report descriptor of a CTAPHID device: usage page 0xF1D0 (FIDO Alliance), usage 0x01
/// (CTAPHID), one 64-byte input report and one 64-byte output report, no report ids.
pub const FIDO_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Var, Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Var, Abs)
    0xc0, // End Collection
];

pub const DEVICE_NAME: &str = "hirz virtual authenticator";
/// pid.codes vendor id for open source hardware.
pub const VENDOR_ID: u32 = 0x1209;
/// A pid.codes test product id (1209:0001 to 1209:0010 are reserved for testing). A
/// dedicated product id must be registered with pid.codes before a stable release; the
/// udev rule in packaging/udev matches on this value.
pub const PRODUCT_ID: u32 = 0x0007;
pub const DEVICE_VERSION: u32 = 0x0001;

/// Size of every report relayed in either direction.
pub const REPORT_SIZE: usize = 64;

/// Creation parameters for the device of `uid`. The decimal uid goes into the `phys` field,
/// where the udev rule reads it (as HID_PHYS) to make the hidraw node owned by that user.
pub fn create_params(phys: &str) -> CreateParams<'_> {
    CreateParams {
        name: DEVICE_NAME,
        phys,
        uniq: "",
        bus: BUS_USB,
        vendor: VENDOR_ID,
        product: PRODUCT_ID,
        version: DEVICE_VERSION,
        country: 0,
        report_descriptor: &FIDO_REPORT_DESCRIPTOR,
    }
}

/// Extracts the 64-byte output report from a UHID_OUTPUT payload. hidraw writers prefix
/// the report with the report number, which is 0 for a descriptor without report ids, so the
/// kernel delivers 65 bytes; a bare 64-byte payload is accepted as well. Anything else is
/// dropped.
pub fn output_report(data: &[u8]) -> Option<[u8; REPORT_SIZE]> {
    let body = match data.len() {
        65 if data.first() == Some(&0) => data.get(1..)?,
        REPORT_SIZE => data,
        _ => return None,
    };
    body.try_into().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_declares_fido_usage() {
        assert_eq!(
            &FIDO_REPORT_DESCRIPTOR[..5],
            &[0x06, 0xd0, 0xf1, 0x09, 0x01]
        );
        assert_eq!(*FIDO_REPORT_DESCRIPTOR.last().unwrap(), 0xc0);
    }

    #[test]
    fn output_report_strips_report_number() {
        let mut d = vec![0u8; 65];
        d[1] = 0xaa;
        d[64] = 0xbb;
        let r = output_report(&d).unwrap();
        assert_eq!(r[0], 0xaa);
        assert_eq!(r[63], 0xbb);
        d[0] = 1;
        assert!(output_report(&d).is_none());
        assert_eq!(output_report(&[7u8; 64]).unwrap(), [7u8; 64]);
        assert!(output_report(&[0u8; 63]).is_none());
        assert!(output_report(&[0u8; 66]).is_none());
    }

    #[test]
    fn params_are_fido_usb() {
        let p = create_params("1000");
        assert_eq!(p.bus, BUS_USB);
        assert_eq!(p.vendor, 0x1209);
        assert!((0x0001..=0x0010).contains(&p.product));
        assert!(hirz_sys::uhid::encode_create2(&p).is_ok());
    }
}
