use std::cmp::min;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

struct Client {
    file: File,
    file_size: u64,
    block_num: u64,
    block_size: u16,
    retransmit_timeout: u8,
    retransmit_count: u8,
    last_transmision: Instant,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2
        || args.contains(&String::from("--help"))
        || args.contains(&String::from("-h"))
    {
        println!("Incorrect usage.");
        println!("");
        println!("stftpd - Simple TFTP Daemon");
        println!("");
        println!("Usage: stftpd [directory...]");
        println!("");
        println!("sftpd is a simple TFTP server that will serve a directory as read only.");
        println!("It doesn't serve sub directories and it does not allow special ");
        println!("characters in the file names.");
        println!("");
        println!("Must be run as root or have the 'cap_net_bind_service' capability.");
        return;
    }

    let directory_name = args.get(1).unwrap();

    let directory = Path::new(directory_name)
        .canonicalize()
        .expect("Invalid Directory Name.");

    let mut active_clients: HashMap<SocketAddr, Client> = HashMap::new();
    let socket = UdpSocket::bind("0.0.0.0:69").expect("Couldn't bind to port. Please run as root.");
    socket
        .set_nonblocking(true)
        .expect("Couldn't set socket to NonBlocking mode.");

    println!("Server Started");
    //Daemon Loop
    loop {
        //Attempt to recieve UDP packet
        let mut buf = [0; 100000];
        let mut recv_result = socket.recv_from(&mut buf);

        while recv_result.is_ok() {
            let (number_of_bytes, client_addr) = recv_result.unwrap();
            let packet_data = buf[..number_of_bytes].to_vec();
            recieve_packet(&packet_data, &client_addr, &mut active_clients, &directory);
            recv_result = socket.recv_from(&mut buf);
        }

        //Process Active Clients

        let client_addresses: Vec<SocketAddr> = active_clients.keys().map(|x| x.clone()).collect();

        for client_address in client_addresses {
            let client = active_clients.get_mut(&client_address).unwrap();
            let timeout_duration = Duration::new(client.retransmit_timeout.into(), 0);
            if Instant::now().duration_since(client.last_transmision) > timeout_duration {
                let data_to_send = get_data_to_send(client);
                let send_result = socket.send_to(&data_to_send, client_address);
                if send_result.is_err() {
                    println!("Failed to send data to {:?}!", client_address);
                    continue;
                }
                client.last_transmision = Instant::now();
            }
        }
        sleep(Duration::new(0, 10000000));
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

            if mode != "octet" {
                println!("Unsuported mode: {} From: {:?}", mode, client_addr);
                return;
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

            let mut file = file_result.unwrap();
            let file_size = file.seek(SeekFrom::End(0)).unwrap();

            //Create Client Entry

            let client = Client {
                file,
                file_size,
                block_num: 1,
                block_size: 512,
                retransmit_timeout: 10,
                retransmit_count: 0,
                last_transmision: Instant::now().checked_sub(Duration::new(100, 0)).unwrap(),
            };

            println!("{:?} Started Downloading: {:?}", client_addr, full_path);
            active_clients.insert(client_addr.clone(), client);
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

            let packet_block_number: u16 = (packet_data[2] as u16) << 8 | (packet_data[3] as u16);

            if !active_clients.contains_key(client_addr) {
                println!("Recieved ACK from unknown Client: {:?}", client_addr);
                return;
            }

            let client = active_clients.get_mut(client_addr).unwrap();

            if client.block_num % 65536 != packet_block_number as u64 {
                println!("Recieved ACK with bad block number.\nLast Block Sent: {}\nAck Block Number: {}", client.block_num, packet_block_number);
            }

            client.block_num += 1;
            client.retransmit_count = 0;
            client.last_transmision = Instant::now().checked_sub(Duration::new(100, 0)).unwrap()
        }

        _ => {
            //Undefined Op
            println!("Undefined OP #{}", op);
            return;
        }
    }
}

fn get_data_to_send(client: &mut Client) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let current_start_byte = (client.block_size as u64) * (client.block_num - 1);
    if current_start_byte > client.file_size {
        return data;
    }
    let wanted_byte_count = min(
        client.block_size as u64,
        client.file_size - current_start_byte,
    );
    let mut read_retry_count = 0;

    let seek_result = client.file.seek(SeekFrom::Start(current_start_byte));
    if seek_result.is_err() {
        println!("Couldn't seek file!");
        return data;
    }

    while data.len() < (wanted_byte_count as usize) && read_retry_count < 3 {
        let mut buf = [0; 10000];
        let read_option = client.file.read(&mut buf[..]);
        if read_option.is_err() {
            println!("Error Reading File!");
            read_retry_count += 1;
            continue;
        }

        let bytes_read = read_option.unwrap();
        data.extend_from_slice(&buf[..bytes_read]);
    }

    data.resize(wanted_byte_count as usize, 0);
    let current_block_u16 = client.block_num as u16;
    data.insert(0, 0x00);
    data.insert(1, 0x03);
    data.insert(2, (current_block_u16 >> 8) as u8);
    data.insert(3, current_block_u16 as u8);
    return data;
}
