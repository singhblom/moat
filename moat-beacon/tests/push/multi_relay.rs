//! A message to a user whose two devices sit on different relays reaches
//! both by push. One test per runtime mix of Alice's devices, `<d1><d2>`.

use moat_beacon::scenarios::multi_relay_push::run;
use moat_beacon::world::ParticipantKind::{DartServer as D, RustCli as R};

macro_rules! cell {
    ($name:ident, $d1:expr, $d2:expr, $cell:literal) => {
        #[test]
        fn $name() {
            let _slot = moat_beacon::parallel::world_slot(super::WORLDS);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build tokio runtime");
            rt.block_on(run($d1, $d2, $cell, true));
        }
    };
}

cell!(multi_relay_push_rr, R, R, "rr");
cell!(multi_relay_push_dd, D, D, "dd");
cell!(multi_relay_push_rd, R, D, "rd");
cell!(multi_relay_push_dr, D, R, "dr");
