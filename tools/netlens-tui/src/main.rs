use std::{collections::HashMap, io::{BufRead, stdout}, path::Path, process::{Child, Command, Stdio, exit}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}, mpsc}, thread, time::{Duration, Instant}};

use blake3::Hash;
use chrono::Local;
use crossterm::{event::{self, Event, KeyCode, KeyEvent, KeyEventKind}, execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}};
use pnet::datalink::NetworkInterface;
use ratatui::{DefaultTerminal, Frame, layout::{Constraint, Direction, Layout}, style::{Color, Style, Stylize}, text::{Line, Masked, Span}, widgets::{BarChart, Block, Cell, List, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Widget}};
use serde::{Deserialize, Serialize};

const EXPECTED_CHECKSUMS: &[(&str, &str)] = &[
    ("nlscan", "2447f8193159a02ea0634a3c881984eb61ed6e10323ef3a2c3b83ebd0198809e"),
    ("nlnetwork", "e5eb07193612e685fd8e6f5aaffa44eb9ae37710432d03e5dc6dbe2ded86728b"),
    ("nltrace", "b6461f73328da58331908b9697f46d9662f2aa80f7a73f6551810be444af08a3"),
    ("maclookup", "bf5ebdf4ea4c4fc99949e2e785f2766e16bd6db50cf92b1ce0d2d1333e5db277"),
];

fn get_bin_checksums() -> Vec<Hash> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scan = std::fs::read(format!("{}/bin/nlscan", root.to_str().unwrap())).unwrap();
    let network = std::fs::read(format!("{}/bin/nlnetwork", root.to_str().unwrap())).unwrap();
    let trace = std::fs::read(format!("{}/bin/nltrace", root.to_str().unwrap())).unwrap();
    let maclookup = std::fs::read(format!("{}/bin/maclookup", root.to_str().unwrap())).unwrap();

    return vec![blake3::hash(&scan), blake3::hash(&network), blake3::hash(&trace), blake3::hash(&maclookup)];
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PacketRes {
    time_epoch: u64,
    packet_type: String,
    mac_source: String,
    mac_destination: String,
    ip_source: String,
    ip_destination: String,
}

#[derive(Debug, Default)]
pub struct App {
    interfaces: Vec<NetworkInterface>,
    current_interface: (String, String, usize),
    current_hosts: Vec<(String, String, String, String, String)>,
    network_hosts: Vec<(String, String, String, String, String)>,
    network_hosts_history: Vec<u64>,
    child_processes: HashMap<String, Child>,
    network_receiver: Option<Arc<Mutex<mpsc::Receiver<String>>>>,
    network_transmitter: Option<mpsc::Sender<String>>,
    update_flag: Arc<AtomicBool>,
    hosts_info_table: Vec<Vec<Cell<'static>>>,
    capture_packets: bool,
    hosts_horizontal_scroll: usize,
    vertical_scroll_state: ScrollbarState,
    vertical_scroll: usize,
    hosts_table_state: TableState,
    pcap_entries: Arc<Mutex<Vec<PacketRes>>>,
    exit: bool
}

pub struct Timer {
    start: Instant,
    duration: Duration
}

impl App {
    fn run_network_scan(&mut self, tx: mpsc::Sender<String>) -> std::io::Result<()> {
        if let Some(child) = self.child_processes.get_mut("network") {
            let _ = child.kill();
            let _ = child.wait();
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let binary_path = format!("{}/bin/nlnetwork", root.to_str().unwrap());

        let mut network_scan = Command::new(binary_path)
            .arg("-j")
            .arg(self.current_interface.1.clone())
            .stdout(Stdio::piped())
            .spawn()?;

        let stdout = network_scan.stdout.take().unwrap();
        thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            while let Ok(bytes) = reader.read_line(&mut line) {
                if bytes == 0 { break; }
                tx.send(line.trim().to_string()).unwrap();
                line.clear();
            }
        });

        self.child_processes.insert("network".to_string(), network_scan);

        Ok(())
    }

    fn poll_network_output(&mut self) {
        if let Some(rx) = &self.network_receiver {
            if let Ok(rx) = rx.clone().lock() {
                while let Ok(line) = rx.try_recv() {
                    let values: Vec<(String, String, String)> = serde_json::from_str(line.as_str()).unwrap();
                    let values = values.iter().map(|v| {
                        let vendor = self.get_vendor(&v.1)
                            .unwrap_or_default()
                            .split(' ')
                            .skip(1)
                            .collect::<Vec<&str>>()
                            .join(" ");

                        (v.0.clone(), v.1.clone(), v.2.clone(), vendor)
                    }).collect::<Vec<(String, String, String, String)>>();
                    self.network_hosts_history.push(values.len() as u64);

                    let values = values.iter().map(|v| {
                        let v = (v.0.clone(), v.1.clone(), v.2.clone(), v.3.clone(), Local::now().format("%H:%M:%S").to_string());

                        let mut exists = false;
                        for host in &self.network_hosts {
                            if host.0 == v.0 {
                                exists = true;
                                break;
                            }
                        }
                        if !exists {
                            self.network_hosts.push(v.clone()); 
                            self.hosts_info_table[0].push(Cell::from(v.0.clone()));
                            self.hosts_info_table[1].push(Cell::from(v.1.clone()));
                            self.hosts_info_table[2].push(Cell::from(v.2.clone()));
                            self.hosts_info_table[3].push(Cell::from(v.3.clone()));
                            self.hosts_info_table[4].push(Cell::from(v.4.clone()));
                        }
                        v
                    }).collect::<Vec<(String, String, String, String, String)>>();

                    self.current_hosts = values;
                    self.update_flag.store(true, Ordering::Relaxed);
                }
            }
        }
    }

    fn run_trace(&mut self) -> std::io::Result<()> {
        if let Some(child) = self.child_processes.get_mut("trace") {
            let _ = child.kill();
            let _ = child.wait();
        }

        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let binary_path = format!("{}/bin/nltrace", root.to_str().unwrap());

        let mut trace_scan = Command::new(binary_path)
            .arg("-i")
            .arg(self.current_interface.0.clone())
            .stdout(Stdio::piped())
            .spawn()?; 

        let stdout = trace_scan.stdout.take().unwrap();
        let entries = self.pcap_entries.clone();

        let update_flag = self.update_flag.clone();
        thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();

            while let Ok(bytes) = reader.read_line(&mut line) {
                if bytes == 0 { break; }

                let trimmed = line.trim().to_string();

                // Try parsing JSON immediately
                if let Ok(mut entries) = entries.lock() {
                    if let Ok(values) = serde_json::from_str::<Vec<PacketRes>>(&trimmed) {
                        for v in values {
                            entries.push(v);
                        }
                    } else if let Ok(value) = serde_json::from_str::<PacketRes>(&trimmed) {
                        entries.push(value);
                    } else {
                        eprintln!("Invalid JSON from trace: {}", trimmed);
                    }
                }

                update_flag.store(true, Ordering::Relaxed);
                line.clear();line.clear();
            }
        });

        self.child_processes.insert("trace".to_string(), trace_scan);
        Ok(())
    }


    fn stop_trace(&mut self) {
        if let Some(child) = self.child_processes.get_mut("trace") {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn get_network_ip(iface: &NetworkInterface) -> String {
        if let Some(ip_network) = iface.ips.iter().find(|ip| ip.is_ipv4()) {
            let network = ip_network.network();
            let prefix = ip_network.prefix();
            return format!("{}/{}", network, prefix);
        }

        return String::new();
    }

    fn stop_children(&mut self) {
        for (_name, child) in self.child_processes.iter_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child_processes.clear();
    }

    fn exit(&mut self) {
        self.stop_children();
        self.exit = true;
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        self.interfaces = pnet::datalink::interfaces();
        self.update_interface(0);
        self.hosts_info_table = vec![vec![Cell::from("IP")], vec![Cell::from("MAC")], vec![Cell::from("HW")], vec![Cell::from("Vendor")], vec![Cell::from("Discovered")]];
        self.hosts_horizontal_scroll = 1;

        let mut command_run_timer = Timer { start: Instant::now(), duration: Duration::from_secs(10) };

        let (tx, rx) = mpsc::channel();
        self.network_transmitter = Some(tx);
        self.network_receiver = Some(Arc::new(Mutex::new(rx)));

        self.run_network_scan(self.network_transmitter.clone().unwrap())?;

        while !self.exit {
            self.poll_network_output();
            terminal.draw(|frame| self.draw(frame))?;
            self.handle_events()?;

            if self.update_flag.load(Ordering::Relaxed) {
                terminal.draw(|frame| self.draw(frame))?;
                self.update_flag.store(false, Ordering::Relaxed);
            }

            if command_run_timer.start.elapsed() >= command_run_timer.duration {
                self.run_network_scan(self.network_transmitter.clone().unwrap())?;
                command_run_timer.start = Instant::now();
            }
        }
        Ok(())
    }

    fn get_vendor(&mut self, mac: &String) -> std::io::Result<String> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let binary_path = format!("{}/bin/maclookup", root.to_str().unwrap());
        let vendor_lookup = Command::new(binary_path)
            .arg(mac)
            .stdout(Stdio::piped())
            .spawn()?;
        
        let stdout = vendor_lookup.stdout.unwrap();

        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        line.trim().to_string();

        Ok(line)
    }

    fn draw(&mut self, frame: &mut Frame) {
        let main_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![
                Constraint::Percentage(5),
                Constraint::Percentage(95)
            ]
        ).split(frame.area());

        // Interfaces
        let iface_block = Block::bordered()
            .title("Interfaces");

        let interface_list = self.interfaces.iter().map(|iface| {
            if iface.name == self.current_interface.0 {
                Span::styled(iface.name.clone(), Style::default().fg(Color::LightYellow))
            } else {
                Span::from(iface.name.clone())
            }
        }).collect::<Vec<Span>>();

        // Add separators between interfaces
        let mut spans_with_sep = Vec::new();
        for (i, span) in interface_list.iter().enumerate() {
            spans_with_sep.push(span.clone());
            if i != interface_list.len() - 1 {
                spans_with_sep.push(Span::raw(" | "));
            }
        }

        let line = Line::from(spans_with_sep);
        let iface_par = Paragraph::new(line).block(iface_block);

        // Data section layout
        let data_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(vec![
                Constraint::Percentage(25),
                Constraint::Percentage(15),
                Constraint::Percentage(60),
            ]).split(main_layout[1]);

        // Network host section
        let first_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![
                Constraint::Percentage(10),
                Constraint::Percentage(90),
            ]).split(data_layout[0]);
        
        let hosts_block = Block::bordered()
            .title("Network hosts");

        let mut hosts = self.network_hosts.clone();
        hosts.insert(0, ("".to_string(), "".to_string(), "".to_string(), "".to_string(), "".to_string()));

        let hosts_list = {
            let width = first_layout[0].width as usize;

            let centered_lines: Vec<Line> = hosts.iter().map(|host| {
                let text = host.clone();

                let len = text.0.len();
                let padding = width.saturating_sub(len) / 2;
                let padded = format!("{}{}", " ".repeat(padding), text.0);

                if self.current_hosts.contains(host) {
                    Line::from(padded)
                } else {
                    Line::styled(padded, Style::default().fg(Color::Red))
                }
            }).collect();

            List::new(centered_lines).block(hosts_block)
        };

        let history_block = Block::bordered()
            .title("Network hosts history");

        let bar_width = 3;
        let max_bars = (first_layout[1].width as usize)/bar_width;
        let start_idx = if self.network_hosts_history.len() >= max_bars {
            self.network_hosts_history.len() - max_bars
        } else {
            0
        };

        let network_hosts_chart = BarChart::default()
            .bar_width(bar_width as u16)
            .bar_gap(0)
            .bar_style(Style::new().fg(Color::LightGreen))
            .data(&self.network_hosts_history[start_idx..].iter().map(|val| ("", val.clone())).collect::<Vec<(&str, u64)>>())
            .block(history_block);

        let hosts_info_block = Block::bordered()
            .title("Host information");

        let hosts_info_table= Table::new(vec![
                Row::new(self.hosts_info_table[0].clone()),
                Row::new(self.hosts_info_table[1].clone()),
                Row::new(self.hosts_info_table[2].clone()),
                Row::new(self.hosts_info_table[3].clone()),
                Row::new(self.hosts_info_table[4].clone())],
            vec![Constraint::Min(20);hosts.len()])
            .column_highlight_style(Style::default().fg(Color::LightYellow))
            .block(hosts_info_block);

        let pcap_block = Block::bordered()
            .title("Network trace");

        if let Ok(entries) = self.pcap_entries.lock() {
            self.vertical_scroll_state = self.vertical_scroll_state.content_length(entries.len());
            let snapshot: Vec<Line> = entries.iter()
                .map(|p| Line::from(format!("{:?}", p)))
                .collect();


            let paragraph = Paragraph::new(snapshot)
                .gray()
                .scroll((self.vertical_scroll as u16, 0));
            
            frame.render_widget(paragraph, data_layout[2]);
        }

        frame.render_widget(iface_par, main_layout[0]);
        frame.render_widget(hosts_list, first_layout[0]);
        frame.render_widget(network_hosts_chart, first_layout[1]);
        frame.render_stateful_widget(hosts_info_table, data_layout[1], &mut self.hosts_table_state);

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            data_layout[2],
            &mut self.vertical_scroll_state,
        );
    }

    fn handle_events(&mut self) -> std::io::Result<()> {
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                    self.handle_key_event(key_event)
                },
                _ => {}
            }
        }

        Ok(())
    }

    fn update_interface(&mut self, index: usize) {
        let iface = self.interfaces[index].clone();
        self.current_interface.0 = iface.name.clone();
        self.current_interface.1 = Self::get_network_ip(&iface);

        self.update_flag.store(true, Ordering::Relaxed);
        self.network_hosts_history.clear();
        self.network_hosts.clear();
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('q') => {
                self.exit();
            },
            KeyCode::Char('l') | KeyCode::Right => {
                if self.hosts_horizontal_scroll < self.network_hosts.len() {
                    self.hosts_horizontal_scroll += 1;
                    self.hosts_table_state.select_column(Some(self.hosts_horizontal_scroll));
                }
            },
            KeyCode::Char('h') | KeyCode::Left => {
                if self.hosts_horizontal_scroll > 1 {
                    self.hosts_horizontal_scroll -= 1;
                    self.hosts_table_state.select_column(Some(self.hosts_horizontal_scroll));
                }
            },
            KeyCode::Char('j') | KeyCode::Down => {
                self.vertical_scroll = self.vertical_scroll.saturating_add(1);
                self.vertical_scroll_state =
                    self.vertical_scroll_state.position(self.vertical_scroll);
            },
            KeyCode::Char('k') | KeyCode::Up => {
                self.vertical_scroll = self.vertical_scroll.saturating_sub(1);
                self.vertical_scroll_state =
                    self.vertical_scroll_state.position(self.vertical_scroll);

            },
            KeyCode::Enter => {
                self.capture_packets = !self.capture_packets;
                if self.capture_packets {
                    let _ = self.run_trace();
                } else {
                    self.stop_trace();
                }
            }
            KeyCode::Tab => {
                if self.current_interface.2 + 1 >= self.interfaces.len() {
                    self.current_interface.2 = 0;
                } else {
                    self.current_interface.2 += 1;
                }
                self.update_interface(self.current_interface.2);
            }
            _ => {}
        }
    }
}

impl Widget for &App {
    fn render(self, area: ratatui::prelude::Rect, buf: &mut ratatui::prelude::Buffer)
        where
            Self: Sized {
    }
}

fn main() {
    let checksums = get_bin_checksums();

    for (i, (_, checksum)) in EXPECTED_CHECKSUMS.iter().enumerate() {
        if checksums[i].to_string() != *checksum {
            eprintln!("FATAL: Binary checksums don't match");
            exit(-1);
        }
    }

    let mut stdout = stdout();
    let _ = enable_raw_mode();
    let _ = execute!(stdout, EnterAlternateScreen);

    let mut terminal = ratatui::init();
    let app = App::default().run(&mut terminal);

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
}