use std::ops::{Add, AddAssign, Sub, SubAssign};

use azalea::{BlockPos, Vec3, core::position::ChunkPos};

pub mod clientbound;
pub mod serverbound;

#[derive(Debug, Clone, Copy)]
pub struct ChunkOffset {
    pub x: i32,
    pub z: i32,
}

impl ChunkOffset {
    pub fn block_x(&self) -> i32 {
        self.x * 16
    }

    pub fn block_z(&self) -> i32 {
        self.z * 16
    }
}

impl ChunkOffset {
    pub fn vec3(&self) -> Vec3 {
        Vec3 {
            x: self.block_x() as f64,
            y: 0.0,
            z: self.block_z() as f64,
        }
    }
}

impl Add<ChunkOffset> for BlockPos {
    type Output = BlockPos;

    fn add(self, rhs: ChunkOffset) -> Self::Output {
        BlockPos {
            x: self.x + rhs.block_x(),
            y: self.y,
            z: self.z + rhs.block_z(),
        }
    }
}

impl AddAssign<ChunkOffset> for BlockPos {
    fn add_assign(&mut self, rhs: ChunkOffset) {
        *self = *self + rhs;
    }
}

impl Sub<ChunkOffset> for BlockPos {
    type Output = BlockPos;

    fn sub(self, rhs: ChunkOffset) -> Self::Output {
        BlockPos {
            x: self.x - rhs.block_x(),
            y: self.y,
            z: self.z - rhs.block_z(),
        }
    }
}

impl SubAssign<ChunkOffset> for BlockPos {
    fn sub_assign(&mut self, rhs: ChunkOffset) {
        *self = *self - rhs;
    }
}

impl Sub<ChunkOffset> for ChunkPos {
    type Output = ChunkPos;

    fn sub(self, rhs: ChunkOffset) -> Self::Output {
        ChunkPos {
            x: self.x - rhs.x,
            z: self.z - rhs.z,
        }
    }
}

impl SubAssign<ChunkOffset> for ChunkPos {
    fn sub_assign(&mut self, rhs: ChunkOffset) {
        *self = *self - rhs;
    }
}
