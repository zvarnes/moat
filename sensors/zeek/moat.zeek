# moat Zeek site policy. Loaded after Zeek's stock site/local.zeek.

@load local
# The Elastic zeek integration expects JSON logs.
@load policy/tuning/json-logs
# community_id lets you pivot between Zeek conn.log and Suricata eve for the same flow.
@load policy/protocols/conn/community-id-logging

# Mirror/SPAN traffic often carries bad checksums (offloading on the sending side);
# don't let Zeek discard those packets.
redef ignore_checksums = T;

# Headroom for traffic bursts on the mirror port.
redef AF_Packet::buffer_size = 128 * 1024 * 1024;

# No zeekctl in the container: Zeek rotates its own logs. The Elastic agent reads the
# live files in /zeek/current; rotated ones move to /zeek/archive and are pruned by run.sh.
redef Log::default_rotation_interval = 1 hr;
redef Log::default_rotation_dir = "/zeek/archive";
