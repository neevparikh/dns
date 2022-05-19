use std::{
  collections::HashMap,
  fmt::Display,
  net::{Ipv4Addr, SocketAddrV4, UdpSocket},
};

use anyhow::Result;
use domain::{
  base::{
    self, iana::Rcode, octets::OctetsRef, Dname, ParsedDname, Question, RecordSection, ToDname,
  },
  rdata::{AllRecordData, Ns, A},
};
use rand::prelude::*;

type Octets = Vec<u8>;
type Message = base::Message<Octets>;
type MessageBuilder = base::MessageBuilder<Octets>;

// Root name server
const ROOT_NAMESERVER: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);
const DNS_PORT: u16 = 53;
const LOCAL_PORT: u16 = 20053;
const OUTBOUND_PORT: u16 = 43210;

struct DnsServer<R: Rng + ?Sized> {
  pub cache: HashMap<Question<Dname<Octets>>, Message>,
  pub socket: UdpSocket,
  pub rng: R,
}

impl DnsServer<ThreadRng> {
  pub fn new() -> Result<DnsServer<ThreadRng>> {
    Ok(DnsServer {
      cache: HashMap::new(),
      socket: UdpSocket::bind(("0.0.0.0", OUTBOUND_PORT))?,
      rng: rand::thread_rng(),
    })
  }
}

impl<R: Rng + ?Sized> DnsServer<R> {
  fn lookup<N: ToDname>(
    &mut self,
    question: &Question<N>,
    name_server: SocketAddrV4,
  ) -> Result<Message> {
    let mut request = MessageBuilder::new_vec().question();
    request.push(question)?;
    request.header_mut().set_rd(true);
    let bytes = request.finish();
    self.socket.send_to(&bytes, name_server)?;
    let mut buf = vec![0u8; 512];
    self.socket.recv_from(&mut buf)?;
    let response = Message::from_octets(buf)?;
    Ok(response)
  }

  fn get_next_server<N: ToDname>(
    &mut self,
    response: &mut Message,
    question: &Question<N>,
  ) -> Result<(bool, Option<SocketAddrV4>)> {
    let (_, answers, authorities, additionals) = response.sections()?;
    let rcode = response.header().rcode();
    let mut answers = answers.peekable();

    if answers.peek().is_some() && rcode == Rcode::NoError {
      return Ok((true, None));
    }

    if rcode == Rcode::NXDomain {
      return Ok((true, None));
    }

    let relevant_hosts: Vec<_> = authorities
      .limit_to::<Ns<ParsedDname<&Octets>>>()
      .filter_map(|record| match record {
        Ok(record) => {
          if question.qname().ends_with(record.owner()) {
            Some(record.data().nsdname().clone())
          } else {
            None
          }
        }
        Err(_) => None,
      })
      .collect();

    let unresolved_ns = relevant_hosts.get(0).cloned();
    let resolved_ns = relevant_hosts
      .into_iter()
      .flat_map(|host| {
        let additionals = additionals.clone();
        let host = host.clone();
        additionals
          .limit_to::<A>()
          .filter_map(move |record| match record {
            Ok(record) => {
              if record.owner().clone() == host {
                Some(record.data().addr())
              } else {
                None
              }
            }
            Err(_) => None,
          })
      })
      .next();

    if let Some(addr) = resolved_ns {
      return Ok((false, Some(SocketAddrV4::new(addr, DNS_PORT))));
    }

    let unresolved_ns = match unresolved_ns {
      Some(name) => name,
      None => return Ok((true, None)),
    };

    // we now need to resolve the unresolved_ns (i.e. find the IP since we don't know it).
    let unresolved_question = Question::new_in(unresolved_ns, base::Rtype::A);
    let resolve_ns = self.recurse(&unresolved_question, false);
    match resolve_ns {
      Ok(msg) => {
        let random_ans = msg.answer()?.limit_to::<A>().choose(&mut self.rng);
        if let Some(Ok(random_ans)) = random_ans {
          let addr = random_ans.data().addr();
          Ok((false, Some(SocketAddrV4::new(addr, DNS_PORT))))
        } else {
          return Ok((true, None));
        }
      }
      Err(_) => return Ok((true, None)),
    }
  }

  fn recurse<N: ToDname + Display>(
    &mut self,
    question: &Question<N>,
    check_cache: bool,
  ) -> Result<Message> {
    let run_lookup = |key: Option<Question<Dname<Octets>>>, dns_server: &mut DnsServer<R>| {
      let server = SocketAddrV4::new(ROOT_NAMESERVER, DNS_PORT);
      println!("Attempting lookup of {question} with {:?}", Some(server));
      let mut response = dns_server.lookup(question, server)?;
      let (mut done, mut name_server) = dns_server.get_next_server(&mut response, question)?;

      loop {
        if !done {
          println!("Attempting lookup of {question} with {:?}", name_server);
        }
        match (done, name_server) {
          (false, Some(server)) => {
            response = dns_server.lookup(question, server)?;
            (done, name_server) = dns_server.get_next_server(&mut response, question)?;
          }
          _ => {
            if let Some(key) = key {
              dns_server.cache.insert(key, response.clone());
            }
            return Ok(response);
          }
        }
      }
    };

    if check_cache {
      let key = Question::<Dname<Octets>>::new(
        question.qname().to_dname()?,
        question.qtype(),
        question.qclass(),
      );
      let cache_val = self.cache.get(&key);
      match cache_val {
        Some(response) => Ok(response.clone()),
        None => run_lookup(Some(key), self),
      }
    } else {
      run_lookup(None, self)
    }
  }

  fn handle_query(&mut self, socket: &UdpSocket, buf: &mut [u8]) -> Result<()> {
    let (_, src) = socket.recv_from(buf)?;
    let request = Message::from_octets(buf.to_vec())?;

    // lookup
    let bytes = if let Ok(question) = request.sole_question() {
      if let Ok(result) = self.recurse(&question, true) {
        println!("Question: {}", question);
        let (_, answers, authorities, additionals) = result.sections()?;
        let mut response =
          MessageBuilder::new_vec().start_answer(&request, result.header().rcode())?;

        let valid_records = |it: RecordSection<_>| {
          it.limit_to_in::<AllRecordData<<&Octets as OctetsRef>::Range, ParsedDname<&Octets>>>()
            .filter_map(|r| r.ok())
        };

        let answers = valid_records(answers);
        let authorities = valid_records(authorities);
        let additionals = valid_records(additionals);

        for record in answers {
          println!("Answer {}", record);
          response.push(record)?;
        }

        let mut response = response.authority();
        for record in authorities {
          // println!("Authority {}", record);
          response.push(record)?;
        }

        let mut response = response.additional();
        for record in additionals {
          // println!("Additional {}", record);
          response.push(record)?;
        }

        response.finish()
      } else {
        MessageBuilder::new_vec()
          .start_answer(&request, Rcode::ServFail)?
          .finish()
      }
    } else {
      MessageBuilder::new_vec()
        .start_answer(&request, Rcode::FormErr)?
        .finish()
    };

    socket.send_to(&bytes, src)?;
    Ok(())
  }
}

fn main() -> Result<()> {
  // Bind an UDP socket on port 2053
  let mut packet_buf = [0u8; 512];
  let socket = UdpSocket::bind(("0.0.0.0", LOCAL_PORT))?;

  let mut server = DnsServer::new()?;

  // For now, queries are handled sequentially, so an infinite loop for servicing
  // requests is initiated.
  loop {
    match server.handle_query(&socket, &mut packet_buf) {
      Ok(_) => {}
      Err(e) => eprintln!("Error: {}", e),
    }
  }
}
