use std::net::UdpSocket;

use anyhow::{anyhow, Result};
use domain::{
  base::{self, iana::Rcode, octets::OctetsRef, ParsedDname, Question, RecordSection, ToDname},
  rdata::AllRecordData,
};

type Octets = Vec<u8>;
type Message = base::Message<Octets>;
type MessageBuilder = base::MessageBuilder<Octets>;

fn lookup<N: ToDname>(question: &Question<N>) -> Result<Message> {
  // Forward queries to Google's public DNS
  let server = ("8.8.8.8", 53);
  let socket = UdpSocket::bind(("0.0.0.0", 43210))?;
  let mut request = MessageBuilder::new_vec().question();
  request.push(question)?;
  request.header_mut().set_rd(true);
  let bytes = request.finish();
  socket.send_to(&bytes, server)?;
  let mut buf = vec![0u8; 512];
  socket.recv_from(&mut buf)?;
  Message::from_octets(buf).map_err(|e| anyhow!("{:?}", e))
}

fn handle_query(socket: &UdpSocket, buf: &mut [u8]) -> Result<()> {
  let (_, src) = socket.recv_from(buf)?;
  let request = Message::from_octets(buf.to_vec())?;

  // lookup
  let bytes = if let Ok(question) = request.sole_question() {
    if let Ok(result) = lookup(&question) {
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
        println!("Authority {}", record);
        response.push(record)?;
      }

      let mut response = response.additional();
      for record in additionals {
        println!("Additional {}", record);
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

fn main() -> Result<()> {
  // Bind an UDP socket on port 2053
  let mut packet_buf = [0u8; 512];
  let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

  // For now, queries are handled sequentially, so an infinite loop for servicing
  // requests is initiated.
  loop {
    match handle_query(&socket, &mut packet_buf) {
      Ok(_) => {}
      Err(e) => eprintln!("Error: {}", e),
    }
  }
}
