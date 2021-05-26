use std::collections::HashMap;
use std::convert::From;

use vaccel_bindings::*;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::virtio::crypto::{Error, Result};
use crate::virtio::DescriptorChain;

use logger::debug;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AccelOp {
    CreateSessionGen,
    DestroySessionGen,
    DoOp,
    Unsupported(u32),
}

impl From<u32> for AccelOp {
    fn from(value: u32) -> Self {
        match value {
            1 => AccelOp::CreateSessionGen,
            2 => AccelOp::DestroySessionGen,
            3 => AccelOp::DoOp,
            v => AccelOp::Unsupported(v),
        }
    }
}

#[derive(Copy, Clone, Default, PartialEq)]
#[repr(C)]
struct AccelRequestHeader {
    pub session_id: u32,
    pub op: u32,
    pub in_nr: u32,
    pub out_nr: u32,
}

unsafe impl ByteValued for AccelRequestHeader {}

pub struct Request {
    // id of the session
    session_id: u32,

    // type of the operation requested
    op_type: AccelOp,

    // Length of "in" data
    in_length: Option<GuestAddress>,

    // Length of "out" data
    out_length: Option<GuestAddress>,

    // VirtIO "in" data
    in_args: Vec<(GuestAddress, u32)>,

    // VirtIO "out" data
    out_args: Vec<(GuestAddress, u32)>,

    // Number of bytes that we will write to the guest as part
    // of the operation
    out_bytes: usize,

    // Guest address for session id
    pub sess_id_addr: Option<GuestAddress>,

    // Guest address for status
    pub status_addr: GuestAddress,
}

fn get_args_vec<'a>(
    desc: DescriptorChain<'a>,
    nr_elements: u32,
    args: &mut Vec<(GuestAddress, u32)>,
) -> Result<(usize, Option<DescriptorChain<'a>>)> {
    let mut curr_desc = desc;
    let mut total_bytes = 0usize;

    for _ in 0..nr_elements {
        args.push((curr_desc.addr, curr_desc.len));
        total_bytes += curr_desc.len as usize;
        curr_desc = curr_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;
    }

    Ok((total_bytes, Some(curr_desc)))
}

impl Request {
    pub fn parse(avail_desc: &DescriptorChain, mem: &GuestMemoryMmap) -> Result<Request> {
        // We must be able to read the request header
        if avail_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        let header = mem
            .read_obj::<AccelRequestHeader>(avail_desc.addr)
            .map_err(Error::GuestMemory)?;

        let mut request = Request {
            session_id: header.session_id,
            op_type: AccelOp::from(header.op),
            in_length: None,
            out_length: None,
            in_args: Vec::new(),
            out_args: Vec::new(),
            out_bytes: 0,
            sess_id_addr: None,
            status_addr: GuestAddress(0),
        };

        // We should at least have a descriptor for the status
        let mut curr_desc = avail_desc
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;

        if header.out_nr > 0 {
            debug!("Getting length of output data GuestAddress");
            if curr_desc.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }

            request.out_length = Some(curr_desc.addr);
            curr_desc = curr_desc
                .next_descriptor()
                .ok_or(Error::DescriptorChainTooShort)?;
        }

        if header.in_nr > 0 {
            debug!("Getting length of input data GuestAddress");
            if curr_desc.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }

            request.in_length = Some(curr_desc.addr);
            curr_desc = curr_desc
                .next_descriptor()
                .ok_or(Error::DescriptorChainTooShort)?;
        }

        debug!("We have: {:?} out args", header.out_nr);
        if header.out_nr > 0 && curr_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        // Read out data
        match get_args_vec(curr_desc, header.out_nr, &mut request.out_args) {
            Ok((_, next_desc)) => {
                curr_desc = next_desc.ok_or(Error::DescriptorChainTooShort)?;
            }
            Err(e) => return Err(e),
        }

        debug!("We have: {:?} in args", header.out_nr);
        if header.in_nr > 0 && !curr_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        // Read in data
        match get_args_vec(curr_desc, header.in_nr, &mut request.in_args) {
            Ok((bytes, next_desc)) => {
                request.out_bytes = bytes;
                curr_desc = next_desc.ok_or(Error::DescriptorChainTooShort)?;
            }
            Err(e) => return Err(e),
        }

        match curr_desc.next_descriptor() {
            Some(last_desc) => {
                request.sess_id_addr = Some(curr_desc.addr);
                request.status_addr = last_desc.addr
            }
            None => request.status_addr = curr_desc.addr,
        }

        Ok(request)
    }

    pub fn execute(
        &mut self,
        sessions: &mut HashMap<u32, Box<vaccel_session>>,
        mem: &GuestMemoryMmap,
    ) -> Result<u32> {
        match self.op_type {
            AccelOp::CreateSessionGen => return self.create_session(sessions, mem),
            AccelOp::DestroySessionGen => return self.close_session(sessions, mem),
            AccelOp::DoOp => return self.do_op(sessions, mem),
            AccelOp::Unsupported(_) => return Err(Error::UnsupportedQueueRequest),
        }
    }

    fn create_session(
        &mut self,
        sessions: &mut HashMap<u32, Box<vaccel_session>>,
        mem: &GuestMemoryMmap,
    ) -> Result<u32> {
        match vaccel_session::new(0) {
            Ok(sess) => {
                mem.write_obj(sess.session_id, self.sess_id_addr.unwrap())
                    .map_err(Error::GuestMemory)?;

                sessions.insert(sess.session_id, Box::new(sess));
                return Ok((self.out_bytes + 4) as u32);
            }
            Err(_) => return Err(Error::VaccelRuntime),
        }
    }

    fn close_session(
        &self,
        sessions: &mut HashMap<u32, Box<vaccel_session>>,
        _mem: &GuestMemoryMmap,
    ) -> Result<u32> {
        match sessions.remove(&self.session_id) {
            Some(sess) => match sess.close() {
                Ok(()) => Ok(0),
                Err(_) => Err(Error::VaccelRuntime),
            },
            None => Err(Error::VaccelRuntime),
        }
    }

    fn do_op(
        &self,
        sessions: &mut HashMap<u32, Box<vaccel_session>>,
        mem: &GuestMemoryMmap,
    ) -> Result<u32> {
        let sess = match sessions.get_mut(&self.session_id) {
            Some(sess) => sess,
            None => return Err(Error::VaccelRuntime),
        };

        let mut read_args = Vec::new();
        for (addr, size) in &self.out_args {
            let host_ptr = mem.get_host_address(*addr).map_err(Error::GuestMemory)?;

            let arg = vaccel_arg {
                size: *size,
                buf: host_ptr as *mut core::ffi::c_void,
            };

            read_args.push(arg);
        }

        let mut write_args = Vec::new();
        for (addr, size) in &self.in_args {
            let host_ptr = mem.get_host_address(*addr).map_err(Error::GuestMemory)?;

            let arg = vaccel_arg {
                size: *size,
                buf: host_ptr as *mut core::ffi::c_void,
            };

            write_args.push(arg);
        }

        match sess.genop(&mut read_args, &mut write_args) {
            Ok(()) => Ok(self.out_bytes as u32),
            Err(_) => Err(Error::VaccelRuntime),
        }
    }
}
