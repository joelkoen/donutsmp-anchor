use std::ops::Sub;

use azalea::Vec3;

#[derive(Debug, Clone, Copy)]
pub struct ChunkOffset {
    pub x: i32,
    pub z: i32,
}

impl ChunkOffset {
    pub fn vec3(&self) -> Vec3 {
        Vec3 {
            x: self.x as f64,
            y: 0.0,
            z: self.z as f64,
        }
    }
}
