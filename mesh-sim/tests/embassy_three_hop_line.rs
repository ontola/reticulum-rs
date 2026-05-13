//! Three OS threads, three Embassy executors, three [`reticulum::transport_embedded::EmbeddedTransport`]
//! instances on a line; B relays between A and C (real `transport_engine` forwarding).

use reticulum_mesh_sim::embassy_mesh::run_three_node_line_relay_harness;

#[test]
fn embassy_three_hop_line_relays_data_through_middle_router() {
    let report = run_three_node_line_relay_harness().expect("harness completes");

    assert!(
        report.node_b_stats.data_forward_queued_count >= 1,
        "middle node should have forwarded at least one data packet: {:?}",
        report.node_b_stats
    );
    assert!(
        report.node_c_stats.data_deliver_local_count >= 1,
        "far end should have delivered locally: {:?}",
        report.node_c_stats
    );
    assert!(
        report.node_a_stats.data_deliver_local_count >= 1,
        "source should have received the echoed packet locally: {:?}",
        report.node_a_stats
    );
}
