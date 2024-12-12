use std::collections::HashMap;
use std::fs::File;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};

fn main() {
    println!("Starting Server");
    let path = Path::new(".").canonicalize().unwrap();
    server(&path);
}

fn server(directory: &PathBuf) {
    let socket = UdpSocket::bind("0.0.0.0:69").expect("Couldn't bind to port. Please run as root.");
    let mut open_files: HashMap<String, File> = HashMap::new();

    loop {
        let mut buf = [0; 100000];
        let (number_of_bytes, client_addr) = socket
            .recv_from(&mut buf)
            .expect("Recieved invalid data on UDP socket.");
        let packet_data = buf[..number_of_bytes].to_vec();

        let tftp_packet = TFTPPacket::decode(&packet_data).unwrap();
        println!("{:?}", tftp_packet);

        match tftp_packet.op {
            Operation::RRQ => {
                let mode = tftp_packet.mode.unwrap();
                if mode != "octet" {
                    println!("Unsupported Mode Requested! Requested Mode: {}", mode);
                    continue;
                }

                let mut filename = tftp_packet.filename.unwrap();
                filename = filename.rsplit("/").nth(0).unwrap().to_string();
                let mut path_buf = directory.clone();
                path_buf.push(filename);
                let path = path_buf.as_path();
                if !path.exists() {
                    println!("File Not Found! File: {:?}", path.to_str());
                    continue;
                }

                let ip_string = client_addr.ip().to_string();
                let file = File::open(path).unwrap();
                open_files.insert(ip_string, file);

                let data_packet = get_data_packet(&file, 1);
            }

            _ => {
                println!("Unsupported Operation");
            }
        }
    }
}

fn get_data_packet(file: &File, data_bloc: u16) -> TFTPPacket {
    let fileoffset =  
}

#[derive(Debug)]
enum Operation {
    RRQ = 1,
    WRQ = 2,
    DATA = 3,
    ACK = 4,
    ERROR = 5,
}

#[derive(Debug)]
struct TFTPPacket {
    op: Operation,
    filename: Option<String>,
    mode: Option<String>,
    block_number: Option<u16>,
    data: Option<Vec<u8>>,
    error_code: Option<u16>,
    error_msg: Option<String>,
}

impl TFTPPacket {
    fn decode(packet_data: &Vec<u8>) -> Option<TFTPPacket> {
        if packet_data.len() < 2 {
            panic!("Recieved undersized packet.")
        }

        let op: u16 = (packet_data[0] as u16) << 8 | (packet_data[1] as u16);

        //Decode based on packet

        match op {
            1 => {
                //Read Request
                if packet_data.len() < 4 {
                    panic!("recieved undersized packet.")
                }
                let file_name_endbyte = packet_data[2..].iter().position(|&x| x == 0).unwrap() + 2;
                let mode_endbyte = packet_data.len() - 1;

                let file_name =
                    String::from_utf8(packet_data[2..file_name_endbyte].to_vec()).unwrap();
                let mode =
                    String::from_utf8(packet_data[file_name_endbyte + 1..mode_endbyte].to_vec())
                        .unwrap()
                        .to_lowercase();

                return Some(TFTPPacket {
                    op: Operation::RRQ,
                    filename: Some(file_name),
                    mode: Some(mode),
                    block_number: None,
                    data: None,
                    error_code: None,
                    error_msg: None,
                });
            }

            2 | 3 => {
                println!("Writing Files is not supported!");
                return None;
            }

            4 => {
                if packet_data.len() != 4 {
                    println!("Recieved ACK of incorrect length! Ignoring.");
                    return None;
                }

                let block_number: u16 = (packet_data[2] as u16) << 8 | (packet_data[3] as u16);

                return Some(TFTPPacket {
                    op: Operation::ACK,
                    filename: None,
                    mode: None,
                    block_number: Some(block_number),
                    data: None,
                    error_code: None,
                    error_msg: None,
                });
            }

            _ => {
                //Undefined Op
                println!("Undefined OP #{}", op);
                return None;
            }
        }
    }
}
