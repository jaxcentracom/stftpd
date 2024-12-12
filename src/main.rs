use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Instant;

struct Client {
    file: File,
    file_size: u64,
    block_num: u64,
    block_size: u16,
    retransmit_timeout: u8,
    retransmit_count: u8,
    last_transmision: Instant,
}

#[derive(Debug)]
enum Operation {
    RRQ = 1,
    WRQ = 2,
    DATA = 3,
    ACK = 4,
    ERROR = 5,
}

fn main() {
    println!("Starting Server");
    let directory = Path::new(".").canonicalize().unwrap();
    let mut active_clients: HashMap<SocketAddr, Client> = HashMap::new();
    let socket = UdpSocket::bind("0.0.0.0:69").expect("Couldn't bind to port. Please run as root.");
    socket
        .set_nonblocking(true)
        .expect("Couldn't set socket to NonBlocking mode.");

    loop {
        //Attempt to recieve UDP packet
        let mut buf = [0; 100000];
        let recv_result = socket.recv_from(&mut buf);

        if recv_result.is_ok() {
            let (number_of_bytes, client_addr) = recv_result.unwrap();
            let packet_data = buf[..number_of_bytes].to_vec();
            recieve_packet(&packet_data, &client_addr, &mut active_clients, &directory);
        }
    }
}

fn is_safe_filename_character(character: char) -> bool {
    let char_value = character as u8;

    //All allowed symbols
    if character == '-' || character == '.' || character == '_' {
        return true;
    }
    //All numbers
    if char_value >= 0x30 && char_value <= 0x39 {
        return true;
    }
    //Upper Case Letters
    if char_value >= 0x41 && char_value <= 0x5A {
        return true;
    }
    //Lower Case Letters
    if char_value >= 0x61 && char_value <= 0x7A {
        return true;
    }

    return false;
}

fn recieve_packet(
    packet_data: &Vec<u8>,
    client_addr: &SocketAddr,
    active_clients: &mut HashMap<SocketAddr, Client>,
    directory: &PathBuf,
) {
    if packet_data.len() < 2 {
        println!("Recieved undersized packet. From {}", client_addr);
        return;
    }

    let op: u16 = (packet_data[0] as u16) << 8 | (packet_data[1] as u16);

    //Decode based on packet

    match op {
        0x01 => {
            //Process Read Request

            let sections: Vec<Vec<u8>> = packet_data[2..packet_data.len() - 1]
                .split(|byte| byte == &0x00)
                .map(|slc| slc.to_vec())
                .collect();
            if sections.len() < 2 || sections.len() % 2 != 0 {
                println!("Recieved Malformed Read Request from {}", client_addr);
                return;
            }

            let file_name = String::from_utf8(sections.get(0).unwrap().clone()).unwrap();
            let mode = String::from_utf8(sections.get(1).unwrap().clone()).unwrap();
            let mut options: HashMap<String, String> = HashMap::new();

            if sections.len() > 2 {
                for i in 0..(sections.len() - 2) / 2 {
                    let option_name =
                        String::from_utf8(sections.get(i * 2 + 2).unwrap().clone()).unwrap();
                    let option_value =
                        String::from_utf8(sections.get(i * 2 + 3).unwrap().clone()).unwrap();

                    options.insert(option_name, option_value);
                }
            }

            //Open File

            let mut filtered_file_name = file_name.clone();
            filtered_file_name.retain(is_safe_filename_character);
            let mut full_path = directory.clone();
            full_path.push(Path::new(&filtered_file_name));

            let file_result = File::open(&full_path);
            if file_result.is_err() {
                println!("Couldn't open file: {:?}", &full_path);
                return;
            }

            let file = file_result.unwrap();

            //Create Client Entry
        }

        2 | 3 => {
            println!("Writing Files is not supported!");
            return;
        }

        4 => {
            if packet_data.len() != 4 {
                println!("Recieved ACK of incorrect length! Ignoring.");
                return;
            }

            let block_number: u16 = (packet_data[2] as u16) << 8 | (packet_data[3] as u16);
        }

        _ => {
            //Undefined Op
            println!("Undefined OP #{}", op);
            return;
        }
    }
}

/*
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
            }

            _ => {
                println!("Unsupported Operation");
            }
        }
    }
}
*/

/*
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
*/
