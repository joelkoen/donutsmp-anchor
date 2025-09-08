use std::sync::Arc;
use std::{error::Error, io::Cursor, sync::LazyLock};

use anyhow::Result;
use azalea::Account;
use azalea::auth::sessionserver::ClientSessionServerError;
use azalea::protocol::connect::{RawReadConnection, RawWriteConnection};
use azalea::protocol::packets::config::ClientboundConfigPacket;
use azalea::protocol::{
    ServerAddress,
    connect::Connection,
    packets::{
        self, ClientIntention, PROTOCOL_VERSION, VERSION_NAME,
        game::{ClientboundGamePacket, ServerboundGamePacket},
        handshake::{
            ClientboundHandshakePacket, ServerboundHandshakePacket,
            s_intention::ServerboundIntention,
        },
        login::{
            ClientboundLoginPacket, ServerboundKey, ServerboundLoginPacket,
            s_hello::ServerboundHello,
        },
        status::{
            ServerboundStatusPacket,
            c_pong_response::ClientboundPongResponse,
            c_status_response::{ClientboundStatusResponse, Players, Version},
        },
    },
    read::ReadPacketError,
    resolver::resolve_address,
};
use futures::FutureExt;
use offset::ChunkOffset;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{Level, debug, error, info, warn};

mod offset;

use crate::offset::{clientbound, serverbound};

const ACCOUNT: &str = "5649";
const LISTEN_ADDR: &str = "127.0.0.1:25566";
const TARGET_ADDR: &str = "donutsmp.net";

const PROXY_DESC: &str = "donutsmp-anchor";
static PROXY_FAVICON: LazyLock<Option<String>> = LazyLock::new(|| None);

static PROXY_VERSION: LazyLock<Version> = LazyLock::new(|| Version {
    name: VERSION_NAME.to_string(),
    protocol: PROTOCOL_VERSION,
});
const PROXY_PLAYERS: Players = Players {
    max: 1,
    online: 0,
    sample: Vec::new(),
};
const PROXY_SECURE_CHAT: Option<bool> = Some(false);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::ERROR)
        .init();

    // Bind to an address and port
    let listener = TcpListener::bind(LISTEN_ADDR).await?;

    info!("Listening on {LISTEN_ADDR}, proxying to {TARGET_ADDR}");

    loop {
        // When a connection is made, pass it off to another thread
        let (stream, _) = listener.accept().await?;
        tokio::spawn(handle_connection(stream));
    }
}

async fn handle_connection(stream: TcpStream) -> anyhow::Result<()> {
    stream.set_nodelay(true)?;
    let ip = stream.peer_addr()?;
    let mut conn: Connection<ServerboundHandshakePacket, ClientboundHandshakePacket> =
        Connection::wrap(stream);

    // The first packet sent from a client is the intent packet.
    // This specifies whether the client is pinging
    // the server or is going to join the game.
    let intent = match conn.read().await {
        Ok(packet) => match packet {
            ServerboundHandshakePacket::Intention(packet) => {
                info!(
                    "New connection from {}, hostname {:?}:{}, version {}, {:?}",
                    ip.ip(),
                    packet.hostname,
                    packet.port,
                    packet.protocol_version,
                    packet.intention
                );
                packet
            }
        },
        Err(e) => {
            let e = e.into();
            warn!("Error during intent: {e}");
            return Err(e);
        }
    };

    match intent.intention {
        // If the client is pinging the proxy,
        // reply with the information below.
        ClientIntention::Status => {
            let mut conn = conn.status();
            loop {
                match conn.read().await {
                    Ok(p) => match p {
                        ServerboundStatusPacket::StatusRequest(_) => {
                            conn.write(ClientboundStatusResponse {
                                description: PROXY_DESC.into(),
                                favicon: PROXY_FAVICON.clone(),
                                players: PROXY_PLAYERS.clone(),
                                version: PROXY_VERSION.clone(),
                                enforces_secure_chat: PROXY_SECURE_CHAT,
                            })
                            .await?;
                        }
                        ServerboundStatusPacket::PingRequest(p) => {
                            conn.write(ClientboundPongResponse { time: p.time }).await?;
                            break;
                        }
                    },
                    Err(e) => match *e {
                        ReadPacketError::ConnectionClosed => {
                            break;
                        }
                        e => {
                            warn!("Error during status: {e}");
                            return Err(e.into());
                        }
                    },
                }
            }
        }
        // If the client intends to join the proxy,
        // wait for them to send the `Hello` packet to
        // log their username and uuid, then forward the
        // connection along to the proxy target.
        ClientIntention::Login => {
            let mut conn = conn.login();
            loop {
                match conn.read().await {
                    Ok(p) => {
                        if let ServerboundLoginPacket::Hello(hello) = p {
                            info!(
                                "Player \'{0}\' from {1} logging in with uuid: {2}",
                                hello.name,
                                ip.ip(),
                                hello.profile_id.to_string()
                            );

                            tokio::spawn(transfer(conn).map(|r| {
                                if let Err(e) = r {
                                    error!("Failed to proxy: {e}");
                                }
                            }));

                            break;
                        }
                    }
                    Err(e) => match *e {
                        ReadPacketError::ConnectionClosed => {
                            break;
                        }
                        e => {
                            warn!("Error during login: {e}");
                            return Err(e.into());
                        }
                    },
                }
            }
        }
        ClientIntention::Transfer => {
            warn!("Client attempted to join via transfer")
        }
    }

    Ok(())
}

async fn transfer(
    mut client_conn: Connection<ServerboundLoginPacket, ClientboundLoginPacket>,
) -> Result<(), Box<dyn Error>> {
    let parsed_target_addr = ServerAddress::try_from(TARGET_ADDR).unwrap();
    let resolved_target_addr = resolve_address(&parsed_target_addr).await?;

    let mut server_conn = Connection::new(&resolved_target_addr).await?;

    let account = Account::microsoft(ACCOUNT).await?;

    server_conn
        .write(ServerboundIntention {
            protocol_version: PROTOCOL_VERSION,
            hostname: parsed_target_addr.host,
            port: parsed_target_addr.port,
            intention: ClientIntention::Login,
        })
        .await?;
    let mut server_conn = server_conn.login();

    // login
    server_conn
        .write(ServerboundHello {
            name: account.username.clone(),
            profile_id: account.uuid.unwrap_or_default(),
        })
        .await?;

    let (server_conn, login_finished) = loop {
        let packet = server_conn.read().await?;

        match packet {
            ClientboundLoginPacket::Hello(p) => {
                // debug!("Got encryption request");
                let e = azalea_crypto::encrypt(&p.public_key, &p.challenge).unwrap();

                if let Some(access_token) = &account.access_token {
                    // keep track of the number of times we tried
                    // authenticating so we can give up after too many
                    let mut attempts: usize = 1;

                    while let Err(e) = {
                        let access_token = access_token.lock().clone();
                        server_conn
                            .authenticate(
                                &access_token,
                                &account
                                    .uuid
                                    .expect("Uuid must be present if access token is present."),
                                e.secret_key,
                                &p,
                            )
                            .await
                    } {
                        if attempts >= 2 {
                            // if this is the second attempt and we failed
                            // both times, give up
                            return Err(e.into());
                        }
                        if matches!(
                            e,
                            ClientSessionServerError::InvalidSession
                                | ClientSessionServerError::ForbiddenOperation
                        ) {
                            // uh oh, we got an invalid session and have
                            // to reauthenticate now
                            account.refresh().await?;
                        } else {
                            return Err(e.into());
                        }
                        attempts += 1;
                    }
                }

                server_conn
                    .write(ServerboundKey {
                        key_bytes: e.encrypted_public_key,
                        encrypted_challenge: e.encrypted_challenge,
                    })
                    .await?;

                server_conn.set_encryption_key(e.secret_key);
            }
            ClientboundLoginPacket::LoginCompression(p) => {
                debug!("Got compression request {:?}", p.compression_threshold);
                server_conn.set_compression_threshold(p.compression_threshold);
            }
            ClientboundLoginPacket::LoginFinished(p) => {
                debug!(
                    "Got profile {:?}. handshake is finished and we're now switching to the configuration state",
                    p.game_profile
                );
                // server_conn.write(ServerboundLoginAcknowledged {}).await?;
                break (server_conn.config(), p);
            }
            ClientboundLoginPacket::LoginDisconnect(p) => {
                error!("Got disconnect {p:?}");
                return Err("Disconnected".into());
            }
            ClientboundLoginPacket::CustomQuery(p) => {
                debug!("Got custom query {:?}", p);
                // replying to custom query is done in
                // packet_handling::login::process_packet_events
            }
            ClientboundLoginPacket::CookieRequest(p) => {
                debug!("Got cookie request {:?}", p);

                server_conn
                    .write(packets::login::ServerboundCookieResponse {
                        key: p.key,
                        // cookies aren't implemented
                        payload: None,
                    })
                    .await?;
            }
        }
    };

    // give the client the login_finished
    // println!("got the login_finished: {:?}", login_finished);
    client_conn.write(login_finished).await?;
    let client_conn = client_conn.config();

    info!("started direct bridging");

    // bridge packets
    let listen_raw_reader = client_conn.reader.raw;
    let listen_raw_writer = client_conn.writer.raw;

    let target_raw_reader = server_conn.reader.raw;
    let target_raw_writer = server_conn.writer.raw;

    let offset_lock: Arc<RwLock<Option<ChunkOffset>>> = Arc::new(RwLock::new(None));

    let copy_listen_to_target = tokio::spawn({
        let offset_lock = offset_lock.clone();
        async move {
            let mut listen_raw_reader = listen_raw_reader;
            let mut target_raw_writer = target_raw_writer;

            loop {
                let mut packet = match listen_raw_reader.read().await {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Error reading packet from listen: {e}");
                        return;
                    }
                };

                // decode as a game packet
                let decoded_packet = azalea::protocol::read::deserialize_packet::<
                    ServerboundGamePacket,
                >(&mut Cursor::new(&packet));
                if let Ok(mut decoded_packet) = decoded_packet {
                    if serverbound::needs_offset(&decoded_packet) {
                        if let Some(offset) = *offset_lock.read().await {
                            serverbound::offset(offset, &mut decoded_packet);
                            packet =
                                azalea::protocol::write::serialize_packet(&decoded_packet).unwrap();
                        } else {
                            error!("packet needed offsetting, but it is not known yet")
                        }
                    }
                }

                match target_raw_writer.write(&packet).await {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Error writing packet to target: {e}");
                        return;
                    }
                }
            }
        }
    });

    let copy_remote_to_local = tokio::spawn({
        async move { remote_to_local(offset_lock.clone(), target_raw_reader, listen_raw_writer).await }
    });

    tokio::try_join!(copy_listen_to_target, copy_remote_to_local,)?;

    Ok(())
}

async fn remote_to_local(
    offset_lock: Arc<RwLock<Option<ChunkOffset>>>,
    target_raw_reader: RawReadConnection,
    listen_raw_writer: RawWriteConnection,
) -> Result<()> {
    let mut target_raw_reader = target_raw_reader;
    let mut listen_raw_writer = listen_raw_writer;

    // changing the order of packets to wait for the offset seems to mess with donutsmp's anticheat
    // isntead, we don't send any packets to the client until we've got the info to be able to reverse the offset
    let mut state = State::Configuration;
    let mut pretick_packets: Vec<Box<[u8]>> = vec![];
    let mut spawn_chunk = (0, 0);

    loop {
        let packet = target_raw_reader.read().await?;
        match &state {
            State::Configuration => {
                let decoded_packet = azalea::protocol::read::deserialize_packet::<
                    ClientboundConfigPacket,
                >(&mut Cursor::new(&packet))?;
                match decoded_packet {
                    ClientboundConfigPacket::FinishConfiguration(_) => {
                        eprintln!("FinishConfiguration");
                        state = State::Preticking;
                    }
                    _ => (),
                }
                listen_raw_writer.write(&packet).await?;
            }

            State::Preticking => {
                let decoded_packet = azalea::protocol::read::deserialize_packet::<
                    ClientboundGamePacket,
                >(&mut Cursor::new(&packet));
                if let Ok(decoded_packet) = decoded_packet {
                    match &decoded_packet {
                        ClientboundGamePacket::Login(login) => {
                            spawn_chunk = match &*login.common.dimension.path {
                                "overworld" => (-2, 1),
                                _ => (0, 0),
                            };
                        }
                        ClientboundGamePacket::SetDefaultSpawnPosition(spawn) => {
                            let x = (spawn.pos.x / 16) + spawn_chunk.0;
                            let z = (spawn.pos.z / 16) + spawn_chunk.1;
                            let offset = ChunkOffset { x, z };
                            eprintln!("offset found: {x} {z}");

                            let mut w = offset_lock.write().await;
                            *w = Some(offset)
                        }
                        ClientboundGamePacket::TickingState(_) => {
                            eprintln!("entered ticking state");
                            state = State::Ticking;
                        }
                        _ => (),
                    }
                }

                pretick_packets.push(packet);

                // State::Preticking -> State::Ticking
                if matches!(state, State::Ticking) {
                    for packet in pretick_packets {
                        let packet = clientbound::handle(&mut state, &offset_lock, packet).await?;
                        listen_raw_writer.write(&packet).await?;
                    }
                    pretick_packets = vec![];
                }
            }
            State::Ticking => {
                let packet = clientbound::handle(&mut state, &offset_lock, packet).await?;
                listen_raw_writer.write(&packet).await?;
            }
        }
    }
}

enum State {
    Configuration,
    Preticking,
    Ticking,
}
