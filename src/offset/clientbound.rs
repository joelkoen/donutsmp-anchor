use std::{io::Cursor, sync::Arc};

use anyhow::{Result, bail};
use azalea::protocol::packets::game::ClientboundGamePacket;
use tokio::sync::RwLock;

use crate::{State, offset::ChunkOffset};

pub async fn handle(
    state: &mut State,
    offset_lock: &Arc<RwLock<Option<ChunkOffset>>>,
    packet: Box<[u8]>,
) -> Result<Box<[u8]>> {
    let decoded_packet = azalea::protocol::read::deserialize_packet::<ClientboundGamePacket>(
        &mut Cursor::new(&packet),
    );

    if let Ok(mut decoded_packet) = decoded_packet {
        match &decoded_packet {
            ClientboundGamePacket::StartConfiguration(_) => {
                let mut w = offset_lock.write().await;
                *w = None;
                *state = State::Configuration;
            }
            _ => (),
        }

        // only attempt to modify + serialize the packet if it needs to be
        if needs_offset(&decoded_packet) {
            if let Some(offset) = *offset_lock.read().await {
                self::offset(offset, &mut decoded_packet);
                return Ok(azalea::protocol::write::serialize_packet(&decoded_packet)?);
            } else {
                bail!("offset is unknown even though we're ticking")
            }
        }
    }

    // forward as is
    Ok(packet)
}

pub fn offset(offset: ChunkOffset, packet: &mut ClientboundGamePacket) {
    match packet {
        ClientboundGamePacket::PlayerPosition(position) => {
            if !position.relative.x {
                position.change.pos.x -= (offset.x * 16) as f64;
            }
            if !position.relative.z {
                position.change.pos.z -= (offset.z * 16) as f64;
            }
        }
        ClientboundGamePacket::AddEntity(entity) => {
            entity.position = entity.position - offset.vec3();
        }
        ClientboundGamePacket::EntityPositionSync(position) => {
            position.values.pos = position.values.pos - offset.vec3();
        }
        ClientboundGamePacket::LevelChunkWithLight(x) => {
            x.x -= offset.x;
            x.z -= offset.z;
        }
        ClientboundGamePacket::SetChunkCacheCenter(x) => {
            x.x -= offset.x;
            x.z -= offset.z;
        }
        ClientboundGamePacket::ForgetLevelChunk(chunk) => {
            chunk.pos -= offset;
        }
        ClientboundGamePacket::ChunksBiomes(chunks) => {
            for chunk in &mut chunks.chunk_biome_data {
                chunk.pos -= offset;
            }
        }
        ClientboundGamePacket::LevelEvent(event) => {
            event.pos -= offset;
        }
        ClientboundGamePacket::LevelParticles(particles) => {
            particles.pos = particles.pos - offset.vec3();
        }
        ClientboundGamePacket::OpenSignEditor(sign) => {
            sign.pos -= offset;
        }
        ClientboundGamePacket::SectionBlocksUpdate(section) => {
            section.section_pos.x -= offset.x;
            section.section_pos.z -= offset.z;
        }
        // ClientboundGamePacket::DamageEvent(x)
        // Explode
        // LightUpdate
        ClientboundGamePacket::Sound(sound) => {
            sound.x -= offset.block_x();
            sound.z -= offset.block_z();
        }
        ClientboundGamePacket::TeleportEntity(entity) => {
            if !entity.relative.x {
                entity.change.pos.x -= (offset.x * 16) as f64;
            }
            if !entity.relative.z {
                entity.change.pos.z -= (offset.z * 16) as f64;
            }
        }
        ClientboundGamePacket::BlockDestruction(block) => {
            block.pos -= offset;
        }
        ClientboundGamePacket::BlockEntityData(block) => {
            block.pos -= offset;
        }
        ClientboundGamePacket::BlockEvent(block) => {
            block.pos -= offset;
        }
        ClientboundGamePacket::BlockUpdate(block) => {
            block.pos -= offset;
        }
        _ => (),
    }
}

pub fn needs_offset(packet: &ClientboundGamePacket) -> bool {
    match packet {
        ClientboundGamePacket::PlayerPosition(_)
        | ClientboundGamePacket::AddEntity(_)
        | ClientboundGamePacket::EntityPositionSync(_)
        | ClientboundGamePacket::LevelChunkWithLight(_)
        | ClientboundGamePacket::SetChunkCacheCenter(_)
        | ClientboundGamePacket::ForgetLevelChunk(_)
        | ClientboundGamePacket::ChunksBiomes(_)
        | ClientboundGamePacket::LevelEvent(_)
        | ClientboundGamePacket::LevelParticles(_)
        | ClientboundGamePacket::OpenSignEditor(_)
        | ClientboundGamePacket::SectionBlocksUpdate(_)
        | ClientboundGamePacket::Sound(_)
        | ClientboundGamePacket::TeleportEntity(_)
        | ClientboundGamePacket::BlockDestruction(_)
        | ClientboundGamePacket::BlockEntityData(_)
        | ClientboundGamePacket::BlockEvent(_)
        | ClientboundGamePacket::BlockUpdate(_) => true,
        _ => false,
    }
}
