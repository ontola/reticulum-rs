//! Serialization and deserialization for Reticulum types.
//!
//! This module provides the [`Serialize`] trait for converting Reticulum
//! types to bytes, and deserialization methods for reconstructing types
//! from bytes.
//!
//! # Overview
//!
//! The serialization system uses a simple byte-based format suitable for
//! network transmission. Types implement [`Serialize`] to write themselves
//! to an [`OutputBuffer`], and provide `deserialize` methods to read from
//! an [`InputBuffer`].
//!
//! # Supported Types
//!
//! - [`AddressHash`] - 16-byte address identifiers
//! - [`Header`] - Packet headers
//! - [`PacketContext`] - Packet context values
//! - [`Packet`] - Complete packets
//!
//! # Usage
//!
//! ```
//! use reticulum::serde::Serialize;
//! use reticulum::buffer::OutputBuffer;
//! use reticulum::packet::Packet;
//!
//! fn serialize_packet(packet: &Packet) -> Vec<u8> {
//!     let mut buf = [0u8; 4096];
//!     let mut output = OutputBuffer::new(&mut buf);
//!     packet.serialize(&mut output).unwrap();
//!     output.as_slice().to_vec()
//! }
//! ```

use crate::{
    buffer::{InputBuffer, OutputBuffer, StaticBuffer},
    error::RnsError,
    hash::AddressHash,
    packet::{Header, HeaderType, Packet, PacketContext},
};

/// Trait for types that can serialize themselves to bytes.
///
/// Implementors of this trait can write their data to an [`OutputBuffer`]
/// for network transmission or storage.
pub trait Serialize {
    /// Serializes the type to the given buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The output buffer to write to
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written
    /// * `Err(RnsError)` - On serialization error
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError>;
}

impl Serialize for AddressHash {
    /// Serializes the address hash to the buffer.
    ///
    /// Writes exactly 16 bytes representing the address hash.
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(self.as_slice())
    }
}

impl Serialize for Header {
    /// Serializes the header to the buffer.
    ///
    /// Writes 2 bytes: the metadata byte and the hops byte.
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[self.to_meta(), self.hops])
    }
}

impl Serialize for PacketContext {
    /// Serializes the packet context to the buffer.
    ///
    /// Writes 1 byte representing the context value.
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[*self as u8])
    }
}

impl Serialize for Packet {
    /// Serializes the packet to the buffer.
    ///
    /// Writes the packet in the following format:
    /// - Header (2 bytes for Type1, 18 bytes for Type2)
    /// - Transport address (16 bytes, Type2 only)
    /// - Destination address (16 bytes)
    /// - Context (1 byte)
    /// - Data (variable length)
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        self.header.serialize(buffer)?;

        if self.header.header_type == HeaderType::Type2 {
            if let Some(transport) = &self.transport {
                transport.serialize(buffer)?;
            }
        }

        self.destination.serialize(buffer)?;

        self.context.serialize(buffer)?;

        buffer.write(self.data.as_slice())
    }
}

impl Header {
    /// Deserializes a header from a buffer.
    ///
    /// Reads 2 bytes: metadata byte and hops byte.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The input buffer to read from
    ///
    /// # Returns
    ///
    /// * `Ok(Header)` - The deserialized header
    /// * `Err(RnsError)` - On error
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<Header, RnsError> {
        let mut header = Header::from_meta(buffer.read_byte()?);
        header.hops = buffer.read_byte()?;

        Ok(header)
    }
}

impl AddressHash {
    /// Deserializes an address hash from a buffer.
    ///
    /// Reads exactly 16 bytes.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The input buffer to read from
    ///
    /// # Returns
    ///
    /// * `Ok(AddressHash)` - The deserialized address hash
    /// * `Err(RnsError)` - On error
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<AddressHash, RnsError> {
        let mut address = AddressHash::new_empty();

        buffer.read(&mut address.as_mut_slice())?;

        Ok(address)
    }
}

impl PacketContext {
    /// Deserializes a packet context from a buffer.
    ///
    /// Reads 1 byte and converts to PacketContext.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The input buffer to read from
    ///
    /// # Returns
    ///
    /// * `Ok(PacketContext)` - The deserialized context
    /// * `Err(RnsError)` - On error
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<PacketContext, RnsError> {
        Ok(PacketContext::from(buffer.read_byte()?))
    }
}

impl Packet {
    /// Deserializes a packet from a buffer.
    ///
    /// Reads the packet in the same format produced by [`Serialize`].
    ///
    /// # Arguments
    ///
    /// * `buffer` - The input buffer to read from
    ///
    /// # Returns
    ///
    /// * `Ok(Packet)` - The deserialized packet
    /// * `Err(RnsError)` - On error
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::buffer::{InputBuffer, OutputBuffer};
    /// use reticulum::packet::{Header, Packet, PacketType, DestinationType, PropagationType, IfacFlag, HeaderType};
    /// use reticulum::hash::AddressHash;
    /// use reticulum::packet::PacketContext;
    /// use reticulum::buffer::StaticBuffer;
    ///
    /// fn roundtrip() {
    ///     let packet = Packet {
    ///         header: Header {
    ///             ifac_flag: IfacFlag::Open,
    ///             header_type: HeaderType::Type1,
    ///             propagation_type: PropagationType::Broadcast,
    ///             destination_type: DestinationType::Single,
    ///             packet_type: PacketType::Data,
    ///             hops: 0,
    ///         },
    ///         ifac: None,
    ///         destination: AddressHash::new_empty(),
    ///         transport: None,
    ///         context: PacketContext::None,
    ///         data: StaticBuffer::new(),
    ///     };
    ///
    ///     let mut out_buf = [0u8; 4096];
    ///     let mut out = OutputBuffer::new(&mut out_buf);
    ///     packet.serialize(&mut out).unwrap();
    ///
    ///     let mut in_buf = InputBuffer::new(out.as_slice());
    ///     let decoded = Packet::deserialize(&mut in_buf).unwrap();
    ///
    ///     assert_eq!(packet.header, decoded.header);
    ///     assert_eq!(packet.destination, decoded.destination);
    /// }
    /// ```
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<Packet, RnsError> {
        let header = Header::deserialize(buffer)?;

        let transport = if header.header_type == HeaderType::Type2 {
            Some(AddressHash::deserialize(buffer)?)
        } else {
            None
        };

        let destination = AddressHash::deserialize(buffer)?;

        let context = PacketContext::deserialize(buffer)?;

        let mut packet = Packet {
            header,
            ifac: None,
            destination,
            transport,
            context,
            data: StaticBuffer::new(),
        };

        buffer.read(&mut packet.data.accuire_buf(buffer.bytes_left()))?;

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::{
        buffer::{InputBuffer, OutputBuffer, StaticBuffer},
        hash::AddressHash,
        packet::{
            DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketType,
            PropagationType,
        },
    };

    use super::Serialize;

    #[test]
    fn serialize_packet() {
        let mut output_data = [0u8; 4096];

        let mut buffer = OutputBuffer::new(&mut output_data);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: StaticBuffer::new(),
        };

        packet.serialize(&mut buffer).expect("serialized packet");

        println!("{}", buffer);
    }

    #[test]
    fn deserialize_packet() {
        let mut output_data = [0u8; 4096];

        let mut buffer = OutputBuffer::new(&mut output_data);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: StaticBuffer::new(),
        };

        packet.data.safe_write(b"Hello, world!");

        packet.serialize(&mut buffer).expect("serialized packet");

        let mut input_buffer = InputBuffer::new(buffer.as_slice());

        let new_packet = Packet::deserialize(&mut input_buffer).expect("deserialized packet");

        assert_eq!(packet.header, new_packet.header);
        assert_eq!(packet.destination, new_packet.destination);
        assert_eq!(packet.transport, new_packet.transport);
        assert_eq!(packet.context, new_packet.context);
        assert_eq!(packet.data.as_slice(), new_packet.data.as_slice());
    }
}
