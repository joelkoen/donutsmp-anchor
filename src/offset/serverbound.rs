use azalea::protocol::packets::game::{ServerboundGamePacket, s_interact::ActionType};

use crate::offset::ChunkOffset;

pub fn offset(offset: ChunkOffset, packet: &mut ServerboundGamePacket) {
    match packet {
        ServerboundGamePacket::BlockEntityTagQuery(block) => {
            block.pos += offset;
        }
        ServerboundGamePacket::MovePlayerPos(player) => {
            player.pos = player.pos + offset.vec3();
        }
        ServerboundGamePacket::MovePlayerPosRot(player) => {
            player.pos = player.pos + offset.vec3();
        }
        ServerboundGamePacket::Interact(interact) => match &mut interact.action {
            ActionType::InteractAt { location, .. } => {
                *location = *location + offset.vec3();
            }
            _ => (),
        },
        ServerboundGamePacket::PlayerAction(action) => {
            action.pos += offset;
        }
        ServerboundGamePacket::UseItemOn(action) => {
            dbg!(&action);
            action.block_hit.block_pos += offset;
            action.block_hit.location = action.block_hit.location + offset.vec3();
            dbg!(&action);
        }
        _ => (),
    }
}

pub fn needs_offset(packet: &ServerboundGamePacket) -> bool {
    match packet {
        ServerboundGamePacket::BlockEntityTagQuery(_)
        | ServerboundGamePacket::MovePlayerPos(_)
        | ServerboundGamePacket::MovePlayerPosRot(_)
        | ServerboundGamePacket::Interact(_)
        | ServerboundGamePacket::PlayerAction(_)
        | ServerboundGamePacket::UseItemOn(_) => true,

        _ => false,
    }
}
