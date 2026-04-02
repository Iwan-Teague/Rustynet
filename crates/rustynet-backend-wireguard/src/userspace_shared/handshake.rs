use std::collections::BTreeMap;

use rustynet_backend_api::NodeId;

#[derive(Debug, Default)]
pub(crate) struct HandshakeTelemetry {
    latest_handshakes_by_node: BTreeMap<NodeId, u64>,
}

impl HandshakeTelemetry {
    pub(crate) fn latest_handshake(&self, node_id: &NodeId) -> Option<u64> {
        self.latest_handshakes_by_node.get(node_id).copied()
    }

    pub(crate) fn record_authenticated_handshake(&mut self, node_id: &NodeId, unix_secs: u64) {
        let entry = self
            .latest_handshakes_by_node
            .entry(node_id.clone())
            .or_insert(unix_secs);
        if unix_secs > *entry {
            *entry = unix_secs;
        }
    }

    pub(crate) fn clear_peer(&mut self, node_id: &NodeId) {
        self.latest_handshakes_by_node.remove(node_id);
    }
}
