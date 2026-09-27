# Mirroring traffic from UniFi to the moat sensor NIC

Goal: copy the traffic on your busiest LAN link to a port that feeds the moat sensor NIC (your USB-C Ethernet adapter), so Zeek and Suricata see it.

```
             Internet
                │
           ┌────┴─────┐
           │ UDM Pro  │  port A ── uplink to main switch / APs  (mirror SOURCE)
           │          │  port B ── moat USB NIC                  (mirror DESTINATION)
           └──────────┘
   moat built-in NIC ── any normal LAN port (management + agent traffic)
```

## 1. Pick the source port

Mirror the port that carries the most client traffic to the gateway, usually the UDM Pro's uplink to your main switch. Because the mirror sits on the LAN side of the gateway, you see real internal IPs before NAT, which is what you want for hunting.

What you will **not** see:

- Traffic between two devices on the same downstream switch (it never reaches the uplink). Mirror that switch's uplink instead, or add a second mirror later.
- WAN-side traffic: UDM Pro WAN/SFP ports generally can't be mirrored. You don't need them.

Inter-VLAN traffic that is routed by the UDM Pro *does* cross the uplink, so it's visible. Mirrored frames keep their 802.1Q VLAN tags; Zeek and Suricata handle tagged traffic.

## 2. Configure the mirror in UniFi Network

Menu names shift between Network app versions; this is the general path.

1. **UniFi Devices** → select the UDM Pro (or the UniFi switch that owns the ports).
2. **Port Manager** → select the **destination** port (where the USB NIC's cable plugs in).
3. Set **Operation / Port Profile** to **Mirroring**, and choose the **source** port from step 1.
4. Apply. The destination port no longer passes normal traffic; it only transmits copies.

Plug the sensor NIC into that destination port. Any spare wired NIC works: a USB-C adapter, or the laptop's built-in port if management runs over Wi-Fi.

## 3. Prepare the sensor NIC on the laptop

Find the adapter name (usually `enx<mac>` for USB NICs):

```bash
./moat preflight          # lists NICs; the USB one shows bus "usb"
```

Make sure NetworkManager / netplan won't put an IP on it. On Ubuntu Desktop, keep the
profile but give it no addresses (this needs no sudo on a desktop session):

```bash
nmcli connection show                       # find the profile for the NIC
nmcli connection modify <profile> ipv4.method disabled ipv6.method disabled
```

On Ubuntu Server (netplan), add to `/etc/netplan/99-moat.yaml` and `sudo netplan apply`:

```yaml
network:
  version: 2
  ethernets:
    enx001122334455:
      dhcp4: false
      dhcp6: false
      link-local: []
      optional: true
```

Capture mode is **optional**: Zeek and Suricata put the NIC in promiscuous mode
themselves, and Suricata disables NIC offloading while it runs. To also force it
at boot (e.g. for ad-hoc tcpdump use):

```bash
sudo apt install -y ethtool tcpdump
sudo ./moat sensor-prep enx001122334455
sudo cp sensors/moat-sensor-nic@.service /etc/systemd/system/
sudo systemctl enable --now moat-sensor-nic@enx001122334455.service
```

## 4. Verify you're seeing mirrored traffic

```bash
sudo timeout 15 tcpdump -ni enx001122334455 -c 50 not arp
# no sudo? use a throwaway container:
docker run --rm --net=host --cap-add=NET_RAW alpine:3.22 sh -c 'apk add -q tcpdump && timeout 15 tcpdump -ni enx001122334455 -c 50 not arp'
```

You should see DNS, TLS, and other traffic from devices **other than the laptop**. Quick checks:

- Only broadcast/multicast (mDNS, SSDP) → the mirror isn't active or the source port is wrong.
- Nothing at all → cable/port, or the interface isn't `up` (`ip link show enx…`).
- Drops under load → `ethtool -S enx… | grep -i drop`. Most USB 1 GbE adapters are fine at home traffic levels.

Record the interface in `.env` as `SENSOR_IFACE=`, then `./moat up` starts Zeek, Suricata and the sensor agent on it.
