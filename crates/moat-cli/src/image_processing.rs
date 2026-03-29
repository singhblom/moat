//! Image processing utilities for the CLI send pipeline.
//!
//! Handles reading, validating, optionally resizing, and generating ThumbHash
//! previews for JPEG and PNG images. Intentionally lives in moat-cli (not
//! moat-core) to keep the core crate lean — the `image` crate is a heavy
//! dependency not needed for crypto or protocol logic.

use image::{DynamicImage, GenericImageView, ImageFormat};
use std::io::Cursor;

/// Maximum pixel dimension (width or height) allowed before resizing.
const MAX_DIMENSION: u32 = 2048;

/// Maximum pixel dimension for ThumbHash input.
const THUMBHASH_MAX_DIM: u32 = 100;

/// Validate, optionally resize, and generate a ThumbHash preview from raw image bytes.
///
/// # Returns
/// `(image_bytes, width, height, thumbhash_bytes, mime_type)`.
/// - `image_bytes` are in the original format (JPEG or PNG), resized if needed.
/// - `mime_type` is `"image/jpeg"` or `"image/png"`.
///
/// # Errors
/// Returns a human-readable error string if the format is unsupported or the
/// image cannot be decoded.
pub fn process_image_from_bytes(
    bytes: &[u8],
) -> Result<(Vec<u8>, u32, u32, Vec<u8>, String), String> {
    // Validate format before full decode (fast, reads only the header).
    let format = image::guess_format(bytes)
        .map_err(|_| "Unsupported format: only JPEG and PNG are accepted".to_string())?;

    let (mime, img_format) = match format {
        ImageFormat::Jpeg => ("image/jpeg", ImageFormat::Jpeg),
        ImageFormat::Png => ("image/png", ImageFormat::Png),
        _ => return Err("Unsupported format: only JPEG and PNG are accepted".to_string()),
    };

    let img = image::load_from_memory(bytes)
        .map_err(|e| format!("Failed to decode image: {}", e))?;

    let (orig_w, orig_h) = img.dimensions();

    // Resize proportionally if either dimension exceeds the limit.
    let (final_bytes, width, height) = if orig_w > MAX_DIMENSION || orig_h > MAX_DIMENSION {
        let (new_w, new_h) = scale_dimensions(orig_w, orig_h, MAX_DIMENSION);
        let resized = img.resize(new_w, new_h, image::imageops::FilterType::Lanczos3);
        let encoded = encode_image(&resized, img_format)?;
        (encoded, new_w, new_h)
    } else {
        (bytes.to_vec(), orig_w, orig_h)
    };

    // Re-decode from final_bytes for ThumbHash generation (covers both resized
    // and original-pass-through cases without keeping two DynamicImage instances).
    let for_hash = image::load_from_memory(&final_bytes)
        .map_err(|e| format!("Failed to re-decode for ThumbHash: {}", e))?;
    let thumbhash = generate_thumbhash(&for_hash);

    Ok((final_bytes, width, height, thumbhash, mime.to_string()))
}


/// Decode a ThumbHash back to a `DynamicImage` for placeholder rendering.
///
/// Returns `None` if the hash is invalid or the decoded RGBA buffer is
/// inconsistent with the reported dimensions.
pub fn decode_thumbhash(hash: &[u8]) -> Option<DynamicImage> {
    let result = std::panic::catch_unwind(|| thumbhash::thumb_hash_to_rgba(hash));
    let (w, h, rgba) = result.ok()?.ok()?;
    image::RgbaImage::from_raw(w as u32, h as u32, rgba).map(DynamicImage::ImageRgba8)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Expand a leading `~` to the home directory.
pub fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = dirs::home_dir() {
            return path.replacen('~', &home.to_string_lossy(), 1);
        }
    }
    path.to_string()
}

/// Scale `(w, h)` proportionally so that neither dimension exceeds `max`.
fn scale_dimensions(w: u32, h: u32, max: u32) -> (u32, u32) {
    let scale = (max as f64 / w.max(h) as f64).min(1.0);
    let new_w = ((w as f64 * scale).round() as u32).max(1);
    let new_h = ((h as f64 * scale).round() as u32).max(1);
    (new_w, new_h)
}

/// Encode a `DynamicImage` into the given format, returning the raw bytes.
fn encode_image(img: &DynamicImage, format: ImageFormat) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), format)
        .map_err(|e| format!("Failed to encode image: {}", e))?;
    Ok(buf)
}

/// Generate a ThumbHash from a `DynamicImage`.
/// Scales down to at most `THUMBHASH_MAX_DIM` × `THUMBHASH_MAX_DIM` first.
fn generate_thumbhash(img: &DynamicImage) -> Vec<u8> {
    let (w, h) = img.dimensions();
    let (tw, th) = scale_dimensions(w, h, THUMBHASH_MAX_DIM);
    let small = if tw < w || th < h {
        img.resize(tw, th, image::imageops::FilterType::Triangle)
    } else {
        img.clone()
    };
    let rgba = small.to_rgba8();
    let (rw, rh) = rgba.dimensions();
    thumbhash::rgba_to_thumb_hash(rw as usize, rh as usize, rgba.as_raw())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jpeg_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = DynamicImage::new_rgb8(w, h);
        encode_image(&img, ImageFormat::Jpeg).expect("test jpeg encoding")
    }

    fn make_png_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = DynamicImage::new_rgba8(w, h);
        encode_image(&img, ImageFormat::Png).expect("test png encoding")
    }

    #[test]
    fn scale_dimensions_reduces_landscape() {
        let (w, h) = scale_dimensions(4096, 2048, 2048);
        assert_eq!(w, 2048);
        assert_eq!(h, 1024);
    }

    #[test]
    fn scale_dimensions_reduces_portrait() {
        let (w, h) = scale_dimensions(1000, 3000, 2048);
        assert_eq!(h, 2048);
        assert!(w < h);
        // Aspect ratio preserved
        let ratio = w as f64 / h as f64;
        assert!((ratio - 1000.0 / 3000.0).abs() < 0.01);
    }

    #[test]
    fn scale_dimensions_no_upscale() {
        let (w, h) = scale_dimensions(100, 100, 2048);
        assert_eq!(w, 100);
        assert_eq!(h, 100);
    }

    #[test]
    fn process_image_small_jpeg_unchanged() {
        let jpeg = make_jpeg_bytes(64, 48);
        let (bytes, w, h, thumbhash, mime) = process_image_from_bytes(&jpeg).unwrap();

        assert_eq!(mime, "image/jpeg");
        assert_eq!(w, 64);
        assert_eq!(h, 48);
        assert!(!thumbhash.is_empty());
        assert!(!bytes.is_empty());
        let decoded = image::load_from_memory(&bytes).unwrap();
        assert_eq!(decoded.dimensions(), (64, 48));
    }

    #[test]
    fn process_image_large_jpeg_resized() {
        let jpeg = make_jpeg_bytes(4096, 2048);
        let (bytes, w, h, thumbhash, mime) = process_image_from_bytes(&jpeg).unwrap();

        assert_eq!(mime, "image/jpeg");
        assert_eq!(w, 2048);
        assert_eq!(h, 1024);
        assert!(!thumbhash.is_empty());
        let decoded = image::load_from_memory(&bytes).unwrap();
        assert_eq!(decoded.dimensions(), (2048, 1024));
    }

    #[test]
    fn process_image_png_accepted() {
        let png = make_png_bytes(32, 32);
        let (_, w, h, _, mime) = process_image_from_bytes(&png).unwrap();

        assert_eq!(mime, "image/png");
        assert_eq!(w, 32);
        assert_eq!(h, 32);
    }

    #[test]
    fn process_image_unsupported_format_rejected() {
        // GIF magic header — format detection should reject it before full decode.
        let gif_magic = b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x3b";
        let err = process_image_from_bytes(gif_magic).unwrap_err();
        assert!(err.contains("Unsupported format"), "unexpected error: {err}");
    }

    #[test]
    fn decode_thumbhash_roundtrip() {
        let img = DynamicImage::new_rgb8(32, 32);
        let hash = generate_thumbhash(&img);
        assert!(!hash.is_empty());

        let decoded = decode_thumbhash(&hash);
        assert!(decoded.is_some());
        let d = decoded.unwrap();
        let (w, h) = d.dimensions();
        assert!(w > 0 && h > 0);
    }

    #[test]
    fn decode_thumbhash_empty_returns_none() {
        assert!(decode_thumbhash(&[]).is_none());
    }
}
