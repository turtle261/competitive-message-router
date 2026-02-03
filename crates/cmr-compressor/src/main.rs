//! Isolated compressor worker process.

use std::io::{BufReader, BufWriter};

use cmr_core::compressor_ipc::{
    CompressorRequest, CompressorResponse, DEFAULT_MAX_FRAME_BYTES, IpcError, read_frame,
    write_frame,
};
use infotheory::{InfotheoryCtx, NcdVariant};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    let ctx = InfotheoryCtx::default();

    loop {
        let req = match read_frame::<CompressorRequest>(&mut reader, DEFAULT_MAX_FRAME_BYTES) {
            Ok(req) => req,
            Err(IpcError::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => {
                let _ = write_frame(
                    &mut writer,
                    &CompressorResponse::Error {
                        message: format!("invalid request: {err}"),
                    },
                );
                break;
            }
        };

        let resp = handle_request(&ctx, req);
        if write_frame(&mut writer, &resp).is_err() {
            break;
        }
    }
}

fn handle_request(ctx: &InfotheoryCtx, req: CompressorRequest) -> CompressorResponse {
    match req {
        CompressorRequest::Health => CompressorResponse::Health { ok: true },
        CompressorRequest::NcdSym { left, right } => CompressorResponse::NcdSym {
            value: ctx.ncd_bytes(&left, &right, NcdVariant::SymVitanyi),
        },
        CompressorRequest::IntrinsicDependence { data, max_order } => {
            CompressorResponse::IntrinsicDependence {
                value: ctx.intrinsic_dependence_bytes(&data, max_order),
            }
        }
        CompressorRequest::BatchNcdSym { target, candidates } => {
            let values = candidates
                .iter()
                .map(|candidate| ctx.ncd_bytes(&target, candidate, NcdVariant::SymVitanyi))
                .collect();
            CompressorResponse::BatchNcdSym { values }
        }
    }
}
